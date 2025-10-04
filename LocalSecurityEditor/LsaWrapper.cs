using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
#if NET5_0_OR_GREATER
using System.Runtime.Versioning;
#endif
using LSA_HANDLE = System.IntPtr;
using System.Threading;

namespace LocalSecurityEditor {
    [StructLayout(LayoutKind.Sequential)]
    struct LSA_OBJECT_ATTRIBUTES {
        internal int Length;
        internal IntPtr RootDirectory;
        internal IntPtr ObjectName;
        internal int Attributes;
        internal IntPtr SecurityDescriptor;
        internal IntPtr SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct LSA_UNICODE_STRING {
        internal ushort Length;
        internal ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string Buffer;
    }
    /// <summary>
    /// Thin managed wrapper around the Windows Local Security Authority (LSA) policy APIs
    /// used to enumerate, add and remove User Rights Assignments for accounts on a machine.
    /// </summary>
    /// <remarks>
    /// Thread safety
    /// - This type is safe to share across threads. It synchronizes access with a per-instance
    ///   ReaderWriterLockSlim.
    /// - Read operations (GetPrivileges, GetPrincipals) enter a read lock and may run in parallel.
    /// - Write operations (AddPrivileges, RemovePrivileges) and Dispose enter a write lock and are
    ///   mutually exclusive with reads and other writes. Dispose blocks until in-flight operations
    ///   complete and then closes the underlying LSA policy handle.
    /// - Methods throw ObjectDisposedException when invoked after Dispose.
    ///
    /// Guidance
    /// - Prefer batching related changes on a single instance. For heavy fan-out reads you may
    ///   create separate instances or rely on concurrent reads via the shared instance.
    /// - LSA calls are blocking; consider calling from background threads (see async wrappers
    ///   on the higher-level UserRights facade) if integrating with UI code.
    /// </remarks>
    public sealed class LsaWrapper : IDisposable {
        private readonly ReaderWriterLockSlim _rwLock = new ReaderWriterLockSlim(LockRecursionPolicy.NoRecursion);
        // Cache for SID -> (domain,name,use) to reduce repeated lookups across calls (bounded LRU)
        private struct SidInfo { public string Domain; public string Name; public SidNameUse Use; }
        private static class SidLruCache {
            private static readonly object _lock = new object();
            private const int Capacity = 4096;
            private static readonly Dictionary<string, SidInfo> _map = new Dictionary<string, SidInfo>(StringComparer.OrdinalIgnoreCase);
            private static readonly LinkedList<string> _lru = new LinkedList<string>();
            private static readonly Dictionary<string, LinkedListNode<string>> _nodes = new Dictionary<string, LinkedListNode<string>>(StringComparer.OrdinalIgnoreCase);

            public static bool TryGet(string key, out SidInfo value) {
                lock (_lock) {
                    if (_map.TryGetValue(key, out value)) {
                        MoveToFront(key);
                        return true;
                    }
                    return false;
                }
            }

            public static void Set(string key, SidInfo value) {
                lock (_lock) {
                    if (_map.ContainsKey(key)) {
                        _map[key] = value;
                        MoveToFront(key);
                        return;
                    }
                    var node = new LinkedListNode<string>(key);
                    _lru.AddFirst(node);
                    _nodes[key] = node;
                    _map[key] = value;
                    if (_map.Count > Capacity) {
                        var last = _lru.Last;
                        if (last != null) {
                            var oldKey = last.Value;
                            _lru.RemoveLast();
                            _nodes.Remove(oldKey);
                            _map.Remove(oldKey);
                        }
                    }
                }
            }

            private static void MoveToFront(string key) {
                if (_nodes.TryGetValue(key, out var node) && node.List != null) {
                    _lru.Remove(node);
                    _lru.AddFirst(node);
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LSA_TRUST_INFORMATION {
            internal LSA_UNICODE_STRING Name;
            internal IntPtr Sid;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct LSA_TRANSLATED_SID2 {
            internal SidNameUse Use;
            internal IntPtr Sid;
            internal int DomainIndex;
            uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct LSA_REFERENCED_DOMAIN_LIST {
            internal uint Entries;
            internal IntPtr Domains;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LSA_ENUMERATION_INFORMATION {
            internal LSA_HANDLE PSid;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LSA_SID {
            internal uint Sid;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LSA_TRANSLATED_NAME {
            internal SidNameUse Use;
            internal LSA_UNICODE_STRING Name;
            internal int DomainIndex;
        }

        enum Access : int {
            POLICY_VIEW_LOCAL_INFORMATION = 0x00000001,
            POLICY_LOOKUP_NAMES = 0x00000800,
            POLICY_READ = 0x00020006,
            POLICY_WRITE = 0x000207F8,
            POLICY_EXECUTE = 0x00020801,
            POLICY_ALL_ACCESS = 0x00F0FFF
        }
        const uint STATUS_ACCESS_DENIED = 0xc0000022;
        const uint STATUS_INSUFFICIENT_RESOURCES = 0xc000009a;
        const uint STATUS_NO_MEMORY = 0xc0000017;
        const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034; //'0x{0:X8}' -f 3221225524
        const uint STATUS_NO_MORE_ENTRIES = 0x8000001a; // '0x{0:X8}' -f 2147483674
        const uint STATUS_SOME_NOT_MAPPED = 0x00000107;
        const uint STATUS_NONE_MAPPED = 0x00000106;
        const uint STATUS_SUCCESS = 0x00000000;
        const uint STATUS_INVALID_PARAMETER = 0xC000000D;
        const uint STATUS_INVALID_HANDLE = 0xC0000008;

        private const int LSA_UNICODE_MAX_BYTES = 0x7ffe; // 32KB - 2 bytes
        IntPtr lsaHandle;
        private readonly string systemName;

        /// <summary>
        /// Creates an instance bound to the local machine.
        /// </summary>
        public LsaWrapper() : this(null) { }

        /// <summary>
        /// Creates an instance bound to a specified remote system or the local
        /// system when <paramref name="systemName"/> is <c>null</c>.
        /// </summary>
        /// <param name="systemName">NetBIOS or DNS name of the target computer, or <c>null</c> for local.</param>
        /// <exception cref="UnauthorizedAccessException">Insufficient rights to open the LSA policy.</exception>
        /// <exception cref="OutOfMemoryException">System reports insufficient resources.</exception>
        /// <exception cref="Win32Exception">Other LSA-related failures. Inspect <see cref="Win32Exception.NativeErrorCode"/>.</exception>
        public LsaWrapper(string systemName) {
            LSA_OBJECT_ATTRIBUTES lsaAttr;
            lsaAttr.RootDirectory = IntPtr.Zero;
            lsaAttr.ObjectName = IntPtr.Zero;
            lsaAttr.Attributes = 0;
            lsaAttr.SecurityDescriptor = IntPtr.Zero;
            lsaAttr.SecurityQualityOfService = IntPtr.Zero;
            lsaAttr.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            lsaHandle = IntPtr.Zero;
            LSA_UNICODE_STRING[] system = null;
            this.systemName = systemName;
            if (systemName != null) {
                system = new LSA_UNICODE_STRING[1];
                system[0] = InitLsaString(systemName);
            }

            // Open with broad access to satisfy enumerate and modify operations reliably (CI often runs elevated)
            uint ret = Win32Sec.LsaOpenPolicy(system, ref lsaAttr, (int)Access.POLICY_ALL_ACCESS, out lsaHandle);
            if (ret == 0) {
                return;
            }
            if (ret == STATUS_NO_MORE_ENTRIES) {
                return;
            }
            if (ret == STATUS_ACCESS_DENIED) {
                throw new UnauthorizedAccessException();
            }
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) {
                throw new OutOfMemoryException();
            }
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        /// <summary>
        /// Returns a list of domain-qualified account names having the specified user right.
        /// </summary>
        /// <param name="privilege">The user right (privilege) to query.</param>
        /// <returns>Array of account names (e.g. <c>DOMAIN\\User</c> or <c>BUILTIN\\Administrators</c>).</returns>
        /// <exception cref="UnauthorizedAccessException">Caller lacks required permissions.</exception>
        /// <exception cref="OutOfMemoryException">System reports insufficient resources.</exception>
        /// <exception cref="Win32Exception">Underlying LSA call failed with a native error.</exception>
        public string[] GetPrivileges(UserRightsAssignment privilege) {
            _rwLock.EnterReadLock();
            try {
                if (lsaHandle == IntPtr.Zero) throw new ObjectDisposedException(nameof(LsaWrapper));
                LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
                privileges[0] = InitLsaString(privilege.ToString());

                IntPtr buffer;
                int count;
                uint ret = Win32Sec.LsaEnumerateAccountsWithUserRight(lsaHandle, privileges, out buffer, out count);

                if (ret != 0) {
                    if (ret == STATUS_ACCESS_DENIED) {
                        throw new UnauthorizedAccessException();
                    }

                    if (ret == STATUS_INSUFFICIENT_RESOURCES || ret == STATUS_NO_MEMORY) {
                        throw new OutOfMemoryException();
                    }

                    // meaning there are no accounts (empty)
                    if (ret == STATUS_NO_MORE_ENTRIES) {
                        return Array.Empty<string>();
                    }

                    throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
                }

                // Build array of LSA_ENUMERATION_INFORMATION for the lookup call
                LSA_ENUMERATION_INFORMATION[] lsaInfo = new LSA_ENUMERATION_INFORMATION[count];
                IntPtr enumOffset = buffer;
                for (int i = 0; i < count; i++) {
                    lsaInfo[i] = Marshal.PtrToStructure<LSA_ENUMERATION_INFORMATION>(enumOffset);
                    enumOffset = IntPtr.Add(enumOffset, Marshal.SizeOf<LSA_ENUMERATION_INFORMATION>());
                }

                // Lookup the SIDs to get domain and account names
                IntPtr domainPtr;
                IntPtr namePtr;
                ret = Win32Sec.LsaLookupSids(lsaHandle, lsaInfo.Length, buffer, out domainPtr, out namePtr);

                if (ret != 0 && ret != STATUS_SOME_NOT_MAPPED && ret != STATUS_NONE_MAPPED) {
                    if (ret == STATUS_ACCESS_DENIED) {
                        throw new UnauthorizedAccessException();
                    }

                    if (ret == STATUS_INSUFFICIENT_RESOURCES || ret == STATUS_NO_MEMORY) {
                        throw new OutOfMemoryException();
                    }

                    throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
                }

                // Marshal translated names
                LSA_TRANSLATED_NAME[] lsaNames = new LSA_TRANSLATED_NAME[count];
                IntPtr nameOffset = namePtr;
                for (int i = 0; i < count; i++) {
                    lsaNames[i] = Marshal.PtrToStructure<LSA_TRANSLATED_NAME>(nameOffset);
                    nameOffset = IntPtr.Add(nameOffset, Marshal.SizeOf<LSA_TRANSLATED_NAME>());
                }

                // Marshal referenced domains list
                LSA_REFERENCED_DOMAIN_LIST domainList = Marshal.PtrToStructure<LSA_REFERENCED_DOMAIN_LIST>(domainPtr);
                string[] domainNames = new string[domainList.Entries];
                IntPtr domainInfoPtr = domainList.Domains;
                for (int i = 0; i < domainList.Entries; i++) {
                    LSA_TRUST_INFORMATION info = Marshal.PtrToStructure<LSA_TRUST_INFORMATION>(domainInfoPtr);
                    domainInfoPtr = IntPtr.Add(domainInfoPtr, Marshal.SizeOf<LSA_TRUST_INFORMATION>());
                    LSA_UNICODE_STRING dname = info.Name;
                    domainNames[i] = TrimLsaString(dname);
                }

                // Build domain-qualified account names
                string[] accountNames = new string[count];
                for (int i = 0; i < lsaNames.Length; i++) {
                    LSA_UNICODE_STRING uname = lsaNames[i].Name;
                    string user = TrimLsaString(uname);
                    int domainIndex = lsaNames[i].DomainIndex;
                    if (domainIndex >= 0 && domainIndex < domainNames.Length && !string.IsNullOrEmpty(domainNames[domainIndex])) {
                        accountNames[i] = domainNames[domainIndex] + "\\" + user;
                    } else {
                        accountNames[i] = user;
                    }
                }

                Win32Sec.LsaFreeMemory(buffer);
                Win32Sec.LsaFreeMemory(domainPtr);
                Win32Sec.LsaFreeMemory(namePtr);

                return accountNames;
            } finally { _rwLock.ExitReadLock(); }
        }

        /// <summary>
        /// Returns rich principal information (both SID and account name) for a given user right.
        /// </summary>
        /// <param name="privilege">The user right (privilege) to query.</param>
        /// <returns>An array of <see cref="PrincipalInfo"/> entries describing principals with the right.</returns>
        /// <exception cref="UnauthorizedAccessException">Caller lacks required permissions.</exception>
        /// <exception cref="OutOfMemoryException">System reports insufficient resources.</exception>
        /// <exception cref="Win32Exception">Underlying LSA call failed with a native error.</exception>
        public PrincipalInfo[] GetPrincipals(UserRightsAssignment privilege) {
            _rwLock.EnterReadLock();
            try {
                if (lsaHandle == IntPtr.Zero) throw new ObjectDisposedException(nameof(LsaWrapper));
                LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
                privileges[0] = InitLsaString(privilege.ToString());

                IntPtr buffer;
                int count;
                uint ret = Win32Sec.LsaEnumerateAccountsWithUserRight(lsaHandle, privileges, out buffer, out count);

                if (ret != 0) {
                    if (ret == STATUS_ACCESS_DENIED) {
                        throw new UnauthorizedAccessException();
                    }
                    if (ret == STATUS_INSUFFICIENT_RESOURCES || ret == STATUS_NO_MEMORY) {
                        throw new OutOfMemoryException();
                    }
                    if (ret == STATUS_NO_MORE_ENTRIES) {
                        return Array.Empty<PrincipalInfo>();
                    }
                    throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
                }

                // Build array of LSA_ENUMERATION_INFORMATION for the lookup call
                LSA_ENUMERATION_INFORMATION[] lsaInfo = new LSA_ENUMERATION_INFORMATION[count];
                IntPtr enumOffset = buffer;
                for (int i = 0; i < count; i++) {
                    lsaInfo[i] = Marshal.PtrToStructure<LSA_ENUMERATION_INFORMATION>(enumOffset);
                    enumOffset = IntPtr.Add(enumOffset, Marshal.SizeOf<LSA_ENUMERATION_INFORMATION>());
                }

                // Lookup the SIDs to get domain and account names
                IntPtr domainPtr;
                IntPtr namePtr;
                ret = Win32Sec.LsaLookupSids(lsaHandle, lsaInfo.Length, buffer, out domainPtr, out namePtr);
                if (ret != 0 && ret != STATUS_SOME_NOT_MAPPED && ret != STATUS_NONE_MAPPED) {
                    if (ret == STATUS_ACCESS_DENIED) {
                        throw new UnauthorizedAccessException();
                    }
                    if (ret == STATUS_INSUFFICIENT_RESOURCES || ret == STATUS_NO_MEMORY) {
                        throw new OutOfMemoryException();
                    }
                    throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
                }

                LSA_TRANSLATED_NAME[] lsaNames = new LSA_TRANSLATED_NAME[count];
                IntPtr nameOffset = namePtr;
                for (int i = 0; i < count; i++) {
                    lsaNames[i] = Marshal.PtrToStructure<LSA_TRANSLATED_NAME>(nameOffset);
                    nameOffset = IntPtr.Add(nameOffset, Marshal.SizeOf<LSA_TRANSLATED_NAME>());
                }

                LSA_REFERENCED_DOMAIN_LIST domainList = Marshal.PtrToStructure<LSA_REFERENCED_DOMAIN_LIST>(domainPtr);
                string[] domainNames = new string[domainList.Entries];
                IntPtr domainInfoPtr = domainList.Domains;
                for (int i = 0; i < domainList.Entries; i++) {
                    LSA_TRUST_INFORMATION info = Marshal.PtrToStructure<LSA_TRUST_INFORMATION>(domainInfoPtr);
                    domainInfoPtr = IntPtr.Add(domainInfoPtr, Marshal.SizeOf<LSA_TRUST_INFORMATION>());
                    LSA_UNICODE_STRING dname = info.Name;
                    domainNames[i] = TrimLsaString(dname);
                }

                var principals = new PrincipalInfo[count];
                for (int i = 0; i < count; i++) {
                    string domain = null;
                    string user = null;
                    if (i < lsaNames.Length) {
                        user = TrimLsaString(lsaNames[i].Name);
                        int idx = lsaNames[i].DomainIndex;
                        if (idx >= 0 && idx < domainNames.Length && !string.IsNullOrEmpty(domainNames[idx])) {
                            domain = domainNames[idx];
                        }
                    }

                    string sidString = TryConvertSidToString(lsaInfo[i].PSid) ?? string.Empty;
                    // Fallback lookup on the target system if unresolved
                    SidNameUse use = (i < lsaNames.Length ? lsaNames[i].Use : SidNameUse.Unknown);
                    if (string.IsNullOrEmpty(user) || use == SidNameUse.Unknown || use == SidNameUse.Invalid) {
                        if (!string.IsNullOrEmpty(sidString) && SidLruCache.TryGet(sidString, out var cached)) {
                            if (!string.IsNullOrEmpty(cached.Name)) user = cached.Name;
                            if (!string.IsNullOrEmpty(cached.Domain)) domain = cached.Domain;
                            if (use == SidNameUse.Unknown || use == SidNameUse.Invalid) use = cached.Use;
                        } else if (TryLookupAccountSidRemote(lsaInfo[i].PSid, out string fDomain, out string fUser, out SidNameUse fUse)) {
                            if (!string.IsNullOrEmpty(fUser)) user = fUser;
                            if (!string.IsNullOrEmpty(fDomain)) domain = fDomain;
                            if (use == SidNameUse.Unknown || use == SidNameUse.Invalid) use = fUse;
                            if (!string.IsNullOrEmpty(sidString)) {
                                SidLruCache.Set(sidString, new SidInfo { Domain = fDomain, Name = fUser, Use = fUse });
                            }
                        }
                    }

                    principals[i] = new PrincipalInfo(sidString, domain, user, use);
                }

                Win32Sec.LsaFreeMemory(buffer);
                Win32Sec.LsaFreeMemory(domainPtr);
                Win32Sec.LsaFreeMemory(namePtr);

                return principals;
            } finally { _rwLock.ExitReadLock(); }
        }

        private static string TryConvertSidToString(IntPtr sidPtr) {
            if (sidPtr == IntPtr.Zero) return null;
            IntPtr strPtr;
            try {
                if (Win32Sec.ConvertSidToStringSid(sidPtr, out strPtr)) {
                    string s = Marshal.PtrToStringUni(strPtr) ?? string.Empty;
                    Win32Sec.LocalFree(strPtr);
                    return s;
                }
            } catch { /* ignore and fallback */ }
            return null;
        }

        private bool TryLookupAccountSidRemote(IntPtr sidPtr, out string domain, out string name, out SidNameUse use) {
            domain = null; name = null; use = SidNameUse.Unknown;
            if (sidPtr == IntPtr.Zero) return false;

            uint nameLen = 0;
            uint domainLen = 0;
            SID_NAME_USE peUse;
            // Probe sizes
            Win32Sec.LookupAccountSid(systemName, sidPtr, null, ref nameLen, null, ref domainLen, out peUse);
            int lastError = Marshal.GetLastWin32Error();
            if (nameLen == 0 && domainLen == 0) {
                return false;
            }

            var nameSb = new StringBuilder((int)nameLen);
            var domainSb = new StringBuilder((int)domainLen);
            bool ok = Win32Sec.LookupAccountSid(systemName, sidPtr, nameSb, ref nameLen, domainSb, ref domainLen, out peUse);
            if (!ok) return false;

            name = nameSb.ToString();
            domain = domainSb.ToString();
            use = MapSidNameUse(peUse);
            return true;
        }

        private static SidNameUse MapSidNameUse(SID_NAME_USE u) {
            switch (u) {
                case SID_NAME_USE.SidTypeUser: return SidNameUse.User;
                case SID_NAME_USE.SidTypeGroup: return SidNameUse.Group;
                case SID_NAME_USE.SidTypeDomain: return SidNameUse.Domain;
                case SID_NAME_USE.SidTypeAlias: return SidNameUse.Alias;
                case SID_NAME_USE.SidTypeWellKnownGroup: return SidNameUse.KnownGroup;
                case SID_NAME_USE.SidTypeDeletedAccount: return SidNameUse.DeletedAccount;
                case SID_NAME_USE.SidTypeInvalid: return SidNameUse.Invalid;
                case SID_NAME_USE.SidTypeUnknown: return SidNameUse.Unknown;
                case SID_NAME_USE.SidTypeComputer: return SidNameUse.Computer;
                default: return SidNameUse.Unknown;
            }
        }

        /// <summary>
        /// Grants a user right to the specified account or SID string.
        /// </summary>
        /// <param name="account">Account name (e.g. <c>DOMAIN\\User</c>, <c>BUILTIN\\Administrators</c>) or SID string.</param>
        /// <param name="privilege">The user right (privilege) to grant.</param>
        /// <exception cref="UnauthorizedAccessException">Caller lacks required permissions.</exception>
        /// <exception cref="OutOfMemoryException">System reports insufficient resources.</exception>
        /// <exception cref="Win32Exception">Underlying LSA call failed with a native error.</exception>
        public void AddPrivileges(string account, UserRightsAssignment privilege) {
            _rwLock.EnterWriteLock();
            try {
                if (lsaHandle == IntPtr.Zero) throw new ObjectDisposedException(nameof(LsaWrapper));
                //IntPtr pSid = GetSIDInformation(account);
                try {
                    uint ret;
                    using (Win32SecurityIdentifier securityIdentifier = new Win32SecurityIdentifier(account)) {
                        LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
                        privileges[0] = InitLsaString(privilege.ToString());
                        ret = Win32Sec.LsaAddAccountRights(lsaHandle, securityIdentifier.Address, privileges, 1);
                    }

                    TestReturnValue(ret);
                } catch {
                    throw;
                }
            } finally { _rwLock.ExitWriteLock(); }
        }

        /// <summary>
        /// Remove principal/account from UserRightsAssignment
        /// </summary>
        /// <param name="account"></param>
        /// <param name="privilege"></param>
        public void RemovePrivileges(string account, UserRightsAssignment privilege) {
            _rwLock.EnterWriteLock();
            try {
                if (lsaHandle == IntPtr.Zero) throw new ObjectDisposedException(nameof(LsaWrapper));
                //IntPtr pSid = GetSIDInformation(account);
                try {
                    uint ret;
                    using (Win32SecurityIdentifier securityIdentifier = new Win32SecurityIdentifier(account)) {
                        LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
                        privileges[0] = InitLsaString(privilege.ToString());
                        ret = Win32Sec.LsaRemoveAccountRights(lsaHandle, securityIdentifier.Address, false, privileges, 1);
                    }

                    TestReturnValue(ret);
                } catch {
                    throw;
                }
            } finally { _rwLock.ExitWriteLock(); }
        }

        /// <summary>
        /// Validates an NTSTATUS-like return value from an LSA call and throws when it indicates failure.
        /// </summary>
        /// <param name="returnValue">The native return value.</param>
        /// <exception cref="UnauthorizedAccessException">Access was denied by the LSA.</exception>
        /// <exception cref="OutOfMemoryException">System reports insufficient resources.</exception>
        /// <exception cref="Win32Exception">For other failures, exposes the translated Win32 error.</exception>
        private static void TestReturnValue(uint returnValue) {
            switch (returnValue) {
                case 0:
                    return;
                case STATUS_NO_MORE_ENTRIES:
                    return;
                case STATUS_ACCESS_DENIED:
                    throw new UnauthorizedAccessException();
                case STATUS_INSUFFICIENT_RESOURCES:
                    throw new OutOfMemoryException();
                case STATUS_NO_MEMORY:
                    throw new OutOfMemoryException();
                case STATUS_OBJECT_NAME_NOT_FOUND:
                    throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)returnValue));
                default:
                    throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)returnValue));
            }
        }

        /// <summary>
        /// Releases the underlying LSA policy handle.
        /// </summary>
        public void Dispose() {
            _rwLock.EnterWriteLock();
            try {
                if (lsaHandle != IntPtr.Zero) {
                    Win32Sec.LsaClose(lsaHandle);
                    lsaHandle = IntPtr.Zero;
                }
            } finally { _rwLock.ExitWriteLock(); }
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Finalizer ensuring that native resources are released when <see cref="Dispose()"/> is not called.
        /// </summary>
        ~LsaWrapper() {
            Dispose();
        }

        private IntPtr GetSIDInformation(string account) {
            LSA_UNICODE_STRING[] names = new LSA_UNICODE_STRING[1];
            LSA_TRANSLATED_SID2 lts;
            IntPtr tsids = IntPtr.Zero;
            IntPtr tdom = IntPtr.Zero;
            names[0] = InitLsaString(account);
            lts.Sid = IntPtr.Zero;
            int ret = Win32Sec.LsaLookupNames2(lsaHandle, 0, 1, names, ref tdom, ref tsids);
            if (ret != 0)
                throw new Win32Exception(Win32Sec.LsaNtStatusToWinError(ret));
            lts = (LSA_TRANSLATED_SID2)Marshal.PtrToStructure(tsids,
            typeof(LSA_TRANSLATED_SID2));
            Win32Sec.LsaFreeMemory(tsids);
            Win32Sec.LsaFreeMemory(tdom);
            return lts.Sid;
        }

        /// <summary>
        /// Creates an <see cref="LSA_UNICODE_STRING"/> from the specified string.
        /// </summary>
        /// <param name="s">The string to convert.</param>
        /// <returns>The initialized <see cref="LSA_UNICODE_STRING"/>.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="s"/> is null or empty.</exception>
        /// <exception cref="ArgumentException">Thrown when the string exceeds 32 KB.</exception>
        private static LSA_UNICODE_STRING InitLsaString(string s) {
            if (string.IsNullOrEmpty(s)) {
                throw new ArgumentNullException(nameof(s));
            }

            // Unicode strings max. 32KB
            if (s.Length > LSA_UNICODE_MAX_BYTES)
                throw new ArgumentException("String too long");
            LSA_UNICODE_STRING lus = new LSA_UNICODE_STRING();
            lus.Buffer = s;
            lus.Length = (ushort)(s.Length * sizeof(char));
            lus.MaximumLength = (ushort)(lus.Length + sizeof(char));

            // If unicode issues then do this instead of previous two line
            //lus.Length = (ushort)(s.Length * 2); // Unicode char is 2 bytes
            //lus.MaximumLength = (ushort)(lus.Length + 2)

            return lus;
        }

        private static string TrimLsaString(LSA_UNICODE_STRING lus) {
            if (lus.Buffer == null) return string.Empty;
            int chars = lus.Length / 2; // Length is bytes
            if (chars <= 0) return string.Empty;
            return (lus.Buffer.Length >= chars) ? lus.Buffer.Substring(0, chars) : lus.Buffer;
        }
    }
}
