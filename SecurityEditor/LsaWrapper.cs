using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.ComponentModel;
using LSA_HANDLE = System.IntPtr;

namespace SecurityEditor {
    // LsaWrapper class credit: Willy Denoyette [MVP]


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
        private bool _writeToConsole = false;

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

        enum SidNameUse : int {
            User = 1,
            Group = 2,
            Domain = 3,
            Alias = 4,
            KnownGroup = 5,
            DeletedAccount = 6,
            Invalid = 7,
            Unknown = 8,
            Computer = 9
        }

        enum Access : int {
            POLICY_READ = 0x20006,
            POLICY_ALL_ACCESS = 0x00F0FFF,
            POLICY_EXECUTE = 0X20801,
            POLICY_WRITE = 0X207F8
        }
        const uint STATUS_ACCESS_DENIED = 0xc0000022;
        const uint STATUS_INSUFFICIENT_RESOURCES = 0xc000009a;
        const uint STATUS_NO_MEMORY = 0xc0000017;

        IntPtr lsaHandle;

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
            if (systemName != null) {
                system = new LSA_UNICODE_STRING[1];
                system[0] = InitLsaString(systemName);
            }

            uint ret = Win32Sec.LsaOpenPolicy(system, ref lsaAttr, (int)Access.POLICY_ALL_ACCESS, out lsaHandle);
            if (ret == 0)
                return;
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
            uint ret =
            Win32Sec.LsaEnumerateAccountsWithUserRight(lsaHandle, privileges, out buffer, out count);

            if (ret != 0) {
                if (ret == STATUS_ACCESS_DENIED) {
                    throw new UnauthorizedAccessException();
                }

                if (ret == STATUS_INSUFFICIENT_RESOURCES || ret == STATUS_NO_MEMORY) {
                    throw new OutOfMemoryException();
                }

                // meaning there are no accounts (empty)
                if (ret == 2147483674) {
                    return new string[count];
                }

                throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
            }

            LSA_ENUMERATION_INFORMATION[] lsaInfo = new LSA_ENUMERATION_INFORMATION[count];
            for (Int64 i = 0, elemOffs = (Int64)buffer; i < count; i++) {
                lsaInfo[i] = (LSA_ENUMERATION_INFORMATION)Marshal.PtrToStructure((IntPtr)elemOffs, typeof(LSA_ENUMERATION_INFORMATION));
                elemOffs += Marshal.SizeOf(typeof(LSA_ENUMERATION_INFORMATION));
            }

            LSA_HANDLE domains;
            LSA_HANDLE names;
            ret = Win32Sec.LsaLookupSids(lsaHandle, lsaInfo.Length, buffer, out domains, out names);

            if (ret != 0) {
                if (ret == STATUS_ACCESS_DENIED) {
                    throw new UnauthorizedAccessException();
                }

                if (ret == STATUS_INSUFFICIENT_RESOURCES || ret == STATUS_NO_MEMORY) {
                    throw new OutOfMemoryException();
                }

                throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
            }

            /*string[] retNames = new string[count];

            LSA_TRANSLATED_NAME[] lsaNames = new LSA_TRANSLATED_NAME[count];
            for (int i = 0, elemOffs = (int)names; i < count; i++)
            {
            lsaNames[i] = (LSA_TRANSLATED_NAME)Marshal.PtrToStructure((LSA_HANDLE)elemOffs, typeof(LSA_TRANSLATED_NAME));
            elemOffs += Marshal.SizeOf(typeof(LSA_TRANSLATED_NAME));

            LSA_UNICODE_STRING name = lsaNames[i].Name;
            retNames[i] = name.Buffer.Substring(0, name.Length / 2);
            }*/

            // Following code also fetches Domains and associates domains and usernames
            string[] retNames = new string[count];
            List<Int64> currentDomain = new List<Int64>();
            int domainCount = 0;

            LSA_TRANSLATED_NAME[] lsaNames = new LSA_TRANSLATED_NAME[count];
            for (Int64 i = 0, elemOffs = (Int64)names; i < count; i++) {
                lsaNames[i] = (LSA_TRANSLATED_NAME)Marshal.PtrToStructure((LSA_HANDLE)elemOffs, typeof(LSA_TRANSLATED_NAME));
                elemOffs += Marshal.SizeOf(typeof(LSA_TRANSLATED_NAME));

                LSA_UNICODE_STRING name = lsaNames[i].Name;
                retNames[i] = name.Buffer.Substring(0, name.Length / 2);

                if (!currentDomain.Contains(lsaNames[i].DomainIndex)) {
                    domainCount = domainCount + 1;
                    currentDomain.Add(lsaNames[i].DomainIndex);
                }
                //Error: not necessary to count domain names

            }

            string[] domainPtrNames = new string[count];

            LSA_REFERENCED_DOMAIN_LIST[] lsaDomainNames = new LSA_REFERENCED_DOMAIN_LIST[count];
            //Error: LSA_REFERENCED_DOMAIN_LIST is a structure, not an array

            for (Int64 i = 0, elemOffs = (Int64)domains; i < count; i++)
            //Error: not necessary
            {
                lsaDomainNames[i] = (LSA_REFERENCED_DOMAIN_LIST)Marshal.PtrToStructure((LSA_HANDLE)elemOffs, typeof(LSA_REFERENCED_DOMAIN_LIST));
                elemOffs += Marshal.SizeOf(typeof(LSA_REFERENCED_DOMAIN_LIST));
            }

            LSA_TRUST_INFORMATION[] lsaDomainName = new LSA_TRUST_INFORMATION[count];
            string[] domainNames = new string[domainCount];

            for (Int64 i = 0, elemOffs = (Int64)lsaDomainNames[i].Domains; i < domainCount; i++) {
                lsaDomainName[i] = (LSA_TRUST_INFORMATION)Marshal.PtrToStructure((LSA_HANDLE)elemOffs, typeof(LSA_TRUST_INFORMATION));
                elemOffs += Marshal.SizeOf(typeof(LSA_TRUST_INFORMATION));

                LSA_UNICODE_STRING tempDomain = lsaDomainName[i].Name;
                //if(tempDomain.Buffer != null)
                //{
                domainNames[i] = tempDomain.Buffer.Substring(0, tempDomain.Length / 2);
                //}
            }

            string[] domainUserName = new string[count];

            for (int i = 0; i < lsaNames.Length; i++) {
                domainUserName[i] = domainNames[lsaNames[i].DomainIndex] + "\\" + retNames[i];
            }

            Win32Sec.LsaFreeMemory(buffer);
            Win32Sec.LsaFreeMemory(domains);
            Win32Sec.LsaFreeMemory(names);

            //return retNames;
            return domainUserName;
        }

        public void AddPrivileges(string account, UserRightsAssignment privilege) {
            IntPtr pSid = GetSIDInformation(account);
            LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
            privileges[0] = InitLsaString(privilege.ToString());
            uint ret = Win32Sec.LsaAddAccountRights(lsaHandle, pSid, privileges, 1);

            if (ret == 0) {
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

        public void RemovePrivileges(string account, UserRightsAssignment privilege) {
            IntPtr pSid = GetSIDInformation(account);
            LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
            privileges[0] = InitLsaString(privilege.ToString());
            uint ret = Win32Sec.LsaRemoveAccountRights(lsaHandle, pSid, false, privileges, 1);

            if (ret == 0) {
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

        private static LSA_UNICODE_STRING InitLsaString(string s) {
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
    }
}
