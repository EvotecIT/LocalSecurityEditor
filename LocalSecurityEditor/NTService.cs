using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;

namespace LocalSecurityEditor {
    /// <summary>
    /// Class to generate a SID for a service name such as NT Service\ADSync, NT Service\MSSQLSERVER, NT Service\himds
    /// </summary>
    public class NTService {
        /// <summary>
        /// Generates the sid for a service name.
        /// </summary>
        /// <param name="serviceName">Name of the service.</param>
        /// <returns>A string representing the SID of the service</returns>
        /// <example>
        /// <code>
        /// string serviceName = "ADSync";
        /// string serviceSid = NTService.GenerateSID(serviceName);
        /// Console.WriteLine("The SID for the service '" + serviceName + "' is: " + serviceSid);
        /// </code>
        /// </example>
        public static string GenerateSID(string serviceName) {
            if (string.IsNullOrWhiteSpace(serviceName)) throw new ArgumentException(nameof(serviceName));
            using (SHA1Managed sha1 = new SHA1Managed()) {
                byte[] serviceNameBytes = Encoding.Unicode.GetBytes(serviceName.ToUpper());
                byte[] hash = sha1.ComputeHash(serviceNameBytes);

                StringBuilder sb = new StringBuilder("S-1-5-80");
                for (int i = 0; i < 5; i++) {
                    sb.Append('-');
                    sb.Append(BitConverter.ToUInt32(hash, i * 4));
                }

                return sb.ToString();
            }
        }

        /// <summary>
        /// Resolves a service name from a provided service SID.
        /// </summary>
        /// <param name="sid">String representation of a service SID.</param>
        /// <returns>The service name if resolved; otherwise, <c>null</c>.</returns>
        /// <example>
        /// <code>
        /// string sid = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
        /// string? serviceName = NTService.ResolveServiceName(sid);
        /// Console.WriteLine("The service for SID '" + sid + "' is: " + serviceName);
        /// </code>
        /// </example>
        public static string? ResolveServiceName(string sid) {
            if (string.IsNullOrWhiteSpace(sid)) throw new ArgumentException(nameof(sid));

            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
                return null;
            }

            if (!ConvertStringSidToSid(sid, out IntPtr sidPtr)) {
                return null;
            }

            try {
                uint nameLen = 0;
                uint domainLen = 0;
                SID_NAME_USE use;

                LookupAccountSid(null, sidPtr, null, ref nameLen, null, ref domainLen, out use);

                StringBuilder name = new StringBuilder((int)nameLen);
                StringBuilder domain = new StringBuilder((int)domainLen);

                if (!LookupAccountSid(null, sidPtr, name, ref nameLen, domain, ref domainLen, out use)) {
                    return null;
                }

                if (domain.ToString().Equals("NT SERVICE", StringComparison.OrdinalIgnoreCase)) {
                    return name.ToString();
                }

                return domain + "\\" + name;
            } finally {
                LocalFree(sidPtr);
            }
        }

        private enum SID_NAME_USE : uint {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer,
            SidTypeLabel
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LookupAccountSid(string? lpSystemName, IntPtr Sid, StringBuilder? Name, ref uint cchName, StringBuilder? ReferencedDomainName, ref uint cchReferencedDomainName, out SID_NAME_USE peUse);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool ConvertStringSidToSid(string StringSid, out IntPtr Sid);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);
    }
}