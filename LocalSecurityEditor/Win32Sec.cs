using System;
using System.Runtime.InteropServices;
using System.Security;

namespace LocalSecurityEditor {
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
    }
}
