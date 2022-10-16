using System;
using System.Security.Principal;
using System.Threading;
using System.Xml.Serialization;
using LocalSecurityEditor;

namespace TestApp {
    internal class Program {
        static void Main() {
            Example1();
            Example2_ExternalComputer();
        }

        private static void Example1() {
            string[] accounts;
            var right = UserRightsAssignment.SeTrustedCredManAccessPrivilege;

            Console.WriteLine("[*] Displaying User Rights Assignment for " + right);

            using (LsaWrapper lsa = new LsaWrapper()) {
                accounts = lsa.GetPrivileges(right);
            }

            foreach (var account in accounts) {
                Console.WriteLine("-> " + account);
            }

            Console.WriteLine("[*] Adding Account EVOTEC\\\\przemyslaw.klys\"");

            using (LsaWrapper lsa = new LsaWrapper()) {
                lsa.AddPrivileges("EVOTEC\\przemyslaw.klys", UserRightsAssignment.SeTrustedCredManAccessPrivilege);
            }

            Console.WriteLine("[*] Removing broken SID ");

            using (LsaWrapper lsa = new LsaWrapper()) {
                try {
                    lsa.RemovePrivileges(@"S-1-5-21-853615985-2870445339-3163598659-4098",
                        UserRightsAssignment.SeTrustedCredManAccessPrivilege);
                } catch (Exception e) {
                    Console.WriteLine("[error] Removing of " + @"S-1-5-21-853615985-2870445339-3163598659-4098" + " failed. Error: " + e.Message);
                }
            }

            Console.WriteLine("[*] Removing broken SID again. Show throw an error. ");

            using (LsaWrapper lsa = new LsaWrapper()) {
                try {
                    lsa.RemovePrivileges(@"S-1-5-21-853615985-2870445339-3163598659-4098",
                        UserRightsAssignment.SeTrustedCredManAccessPrivilege);
                } catch (Exception e) {
                    Console.WriteLine("[error] Removing of " + @"S-1-5-21-853615985-2870445339-3163598659-4098" + " failed. Error: " + e.Message);
                }
            }

            using (LsaWrapper lsa = new LsaWrapper()) {
                accounts = lsa.GetPrivileges(UserRightsAssignment.SeTrustedCredManAccessPrivilege);
            }

            Console.WriteLine("[*] Displaying User Rights Assignment for " + right);
            foreach (var account in accounts) {
                Console.WriteLine("-> " + account);
            }

            Console.WriteLine("[*] Adding broken SID ");
            using (LsaWrapper lsa = new LsaWrapper()) {
                lsa.AddPrivileges(@"S-1-5-21-853615985-2870445339-3163598659-4098", UserRightsAssignment.SeTrustedCredManAccessPrivilege);
            }
        }

        private static void Example2_ExternalComputer() {
            string[] accounts;

            Console.WriteLine("[*] Accessing AD1 server - Displaying Current");

            Thread.Sleep(2000);

            using (LsaWrapper lsa = new LsaWrapper("AD1")) {
                accounts = lsa.GetPrivileges(UserRightsAssignment.SeBatchLogonRight);
            }

            foreach (var account in accounts) {
                Console.WriteLine(account);
            }

            Console.WriteLine("[*] Adding Account EVOTEC\\\\przemyslaw.klys\"");

            using (LsaWrapper lsa = new LsaWrapper("AD1")) {
                lsa.AddPrivileges("EVOTEC\\przemyslaw.klys", UserRightsAssignment.SeBatchLogonRight);
            }

            Thread.Sleep(2000);

            Console.WriteLine("[*] Accessing AD1 server - Displaying Current");

            using (LsaWrapper lsa = new LsaWrapper("AD1")) {
                accounts = lsa.GetPrivileges(UserRightsAssignment.SeBatchLogonRight);
            }

            foreach (var account in accounts) {
                Console.WriteLine(account);
            }

            Console.WriteLine("[*] Accessing AD1 server - Removing User");

            Thread.Sleep(2000);

            using (LsaWrapper lsa = new LsaWrapper("AD1")) {
                lsa.RemovePrivileges(@"EVOTEC\przemyslaw.klys", UserRightsAssignment.SeBatchLogonRight);
            }

            Thread.Sleep(2000);

            Console.WriteLine("[*] Accessing AD1 server - Displaying Current");

            using (LsaWrapper lsa = new LsaWrapper("AD1")) {
                accounts = lsa.GetPrivileges(UserRightsAssignment.SeBatchLogonRight);
            }

            foreach (var account in accounts) {
                Console.WriteLine(account);
            }
        }
    }
}
