using System;
using System.Security.Cryptography;
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
    }
}