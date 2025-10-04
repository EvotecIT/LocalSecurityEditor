using System;
using System.ComponentModel;
using System.Text;
using System.Runtime.InteropServices;
using LSA_HANDLE = System.IntPtr;

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


    public sealed class LsaWrapper : IDisposable {
        // obsolete field removed

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

        IntPtr lsaHandle;
        private readonly string systemName;

        public LsaWrapper() : this(null) { }
        // // local system if systemName is null
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

            // Use minimal required access; lookup names covers enumerate/add/remove rights operations
            uint ret = Win32Sec.LsaOpenPolicy(system, ref lsaAttr, (int)Access.POLICY_LOOKUP_NAMES, out lsaHandle);
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

        public string[] GetPrivileges(UserRightsAssignment privilege) {
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
                    return new string[0];
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
        }

        /// <summary>
        /// Returns rich principal information (both SID and account name) for a given right.
        /// </summary>
        public PrincipalInfo[] GetPrincipals(UserRightsAssignment privilege) {
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
                    return new PrincipalInfo[0];
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
                    if (TryLookupAccountSidRemote(lsaInfo[i].PSid, out string fDomain, out string fUser, out SidNameUse fUse)) {
                        if (!string.IsNullOrEmpty(fUser)) user = fUser;
                        if (!string.IsNullOrEmpty(fDomain)) domain = fDomain;
                        if (use == SidNameUse.Unknown || use == SidNameUse.Invalid) use = fUse;
                    }
                }

                principals[i] = new PrincipalInfo(sidString, domain, user, use);
            }

            Win32Sec.LsaFreeMemory(buffer);
            Win32Sec.LsaFreeMemory(domainPtr);
            Win32Sec.LsaFreeMemory(namePtr);

            return principals;
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
        /// Add principal/account to UserRightsAssignment
        /// </summary>
        /// <param name="account"></param>
        /// <param name="privilege"></param>
        public void AddPrivileges(string account, UserRightsAssignment privilege) {
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
        }

        /// <summary>
        /// Remove principal/account from UserRightsAssignment
        /// </summary>
        /// <param name="account"></param>
        /// <param name="privilege"></param>
        public void RemovePrivileges(string account, UserRightsAssignment privilege) {
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
        }

        /// <summary>
        /// Throws error if there's anything else then 0
        /// </summary>
        /// <param name="returnValue"></param>
        /// <exception cref="UnauthorizedAccessException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        /// <exception cref="Win32Exception"></exception>
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
        /// Dispose LsaWrapper
        /// </summary>
        public void Dispose() {
            if (lsaHandle != IntPtr.Zero) {
                Win32Sec.LsaClose(lsaHandle);
                lsaHandle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }

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
            if (s.Length > 0x7ffe)
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
