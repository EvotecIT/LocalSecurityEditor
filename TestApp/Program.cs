using System;
using LocalSecurityEditor;

namespace TestApp {
    internal class Program {
        static void Main() {
            string[] accounts;

            Console.WriteLine("[*] Accessing AD1 server - Displaying Current");

            using (LsaWrapper lsa = new LsaWrapper("AD1")) {
                accounts = lsa.GetPrivileges(UserRightsAssignment.SeBatchLogonRight);
            }

            foreach (var account in accounts) {
                Console.WriteLine(account);
            }

            Console.WriteLine("[*] Adding Account to the Server");

            using (LsaWrapper lsa = new LsaWrapper("AD1")) {
                lsa.AddPrivileges("EVOTEC\\przemyslaw.klys", UserRightsAssignment.SeBatchLogonRight);
            }

            Console.WriteLine("[*] Accessing AD1 server - Displaying Current");

            using (LsaWrapper lsa = new LsaWrapper("AD1")) {
                accounts = lsa.GetPrivileges(UserRightsAssignment.SeBatchLogonRight);
            }

            foreach (var account in accounts) {
                Console.WriteLine(account);
            }

            Console.WriteLine("[*] Accessing AD1 server - Displaying Current");

            using (LsaWrapper lsa = new LsaWrapper("AD1")) {
                lsa.RemovePrivileges("EVOTEC\\przemyslaw.klys", UserRightsAssignment.SeBatchLogonRight);
            }

            using (LsaWrapper lsa = new LsaWrapper("AD1")) {
                accounts = lsa.GetPrivileges(UserRightsAssignment.SeBatchLogonRight);
            }

            foreach (var account in accounts) {
                Console.WriteLine(account);
            }
        }
    }
}
