using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace LocalSecurityEditor {
    internal enum SID_NAME_USE {
        SidTypeUser = 1,
        SidTypeGroup,
        SidTypeDomain,
        SidTypeAlias,
        SidTypeWellKnownGroup,
        SidTypeDeletedAccount,
        SidTypeInvalid,
        SidTypeUnknown,
        SidTypeComputer
    }

    sealed class Win32Sec {
        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurity]
        internal static extern uint LsaOpenPolicy(
            LSA_UNICODE_STRING[] SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            int AccessMask,
            out IntPtr PolicyHandle
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurity]
        internal static extern uint LsaAddAccountRights(
            IntPtr PolicyHandle,
            IntPtr pSID,
            LSA_UNICODE_STRING[] UserRights,
            int CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurity]
        internal static extern uint LsaRemoveAccountRights(
            IntPtr PolicyHandle,
            IntPtr pSID,
            bool allRights,
            LSA_UNICODE_STRING[] UserRights,
            int CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurity]
        internal static extern uint LsaEnumerateAccountsWithUserRight(
            IntPtr PolicyHandle,
            LSA_UNICODE_STRING[] UserRights,
            out IntPtr EnumerationBuffer,
            out int CountReturned
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurity]
        internal static extern uint LsaEnumerateAccountRights(
            IntPtr PolicyHandle,
            IntPtr AccountSid,
            out IntPtr UserRights,
            out ulong CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurity]
        internal static extern uint LsaLookupSids(
            IntPtr PolicyHandle,
            int count,
            IntPtr buffer,
            out IntPtr domainList,
            out IntPtr nameList
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurity]
        internal static extern int LsaLookupNames2(
            IntPtr PolicyHandle,
            uint Flags,
            uint Count,
            LSA_UNICODE_STRING[] Names,
            ref IntPtr ReferencedDomains,
            ref IntPtr Sids
        );

        [DllImport("advapi32")]
        internal static extern int LsaNtStatusToWinError(int NTSTATUS);

        [DllImport("advapi32")]
        internal static extern int LsaClose(IntPtr PolicyHandle);

        [DllImport("advapi32")]
        internal static extern int LsaFreeMemory(IntPtr Buffer);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool ConvertSidToStringSid(IntPtr Sid, out IntPtr StringSid);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true), SuppressUnmanagedCodeSecurity]
        internal static extern bool LookupAccountName(
            string lpSystemName,
            string lpAccountName,
            byte[] Sid,
            ref uint cbSid,
            StringBuilder ReferencedDomainName,
            ref uint cchReferencedDomainName,
            out SID_NAME_USE peUse
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true), SuppressUnmanagedCodeSecurity]
        internal static extern bool LookupAccountSid(
            string lpSystemName,
            IntPtr Sid,
            StringBuilder Name,
            ref uint cchName,
            StringBuilder ReferencedDomainName,
            ref uint cchReferencedDomainName,
            out SID_NAME_USE peUse
        );

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode), SuppressUnmanagedCodeSecurity]
        internal static extern uint NetAddServiceAccount(
            string ServerName,
            string AccountName,
            string Reserved,
            uint Flags
        );

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode), SuppressUnmanagedCodeSecurity]
        internal static extern uint NetIsServiceAccount(
            string ServerName,
            string AccountName,
            out bool IsService
        );

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode), SuppressUnmanagedCodeSecurity]
        internal static extern uint NetRemoveServiceAccount(
            string ServerName,
            string AccountName,
            int Flags
        );
    }
}
