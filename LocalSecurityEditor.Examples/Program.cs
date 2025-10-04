using System;
using System.Security.Principal;
using System.Threading;
using System.Xml.Serialization;

using LocalSecurityEditor;

namespace TestApp {
    internal class Program {
        static void Main() {
            // Basic local enumeration using the OO API
            Example_UserRightsApi_Local();

            // Remote machine sample
            // Example_UserRightsApi_Remote("AD1");

            // Low-level LsaWrapper examples
            // Example1();
            // Example2_ExternalComputer();
            ExampleCoversion();
        }

        private static void Example_UserRightsApi_Local() {
            // enumerate all rights and dump counts
            var all = UserRights.Get();
            foreach (var ura in all) {
                Console.WriteLine($"{ura.ShortName}: {ura.Count} principals");
            }

            // single right via extension method
            var serviceLogon = UserRightsAssignment.SeServiceLogonRight.Get();
            foreach (var p in serviceLogon.Principals) {
                Console.WriteLine($"SERVICE LOGON -> {p.AccountName} ({p.SidString})");
            }
        }

        private static void Example_UserRightsApi_Remote(string computer) {
            using (var ur = new UserRights(computer)) {
                // add by account name or SID
                ur.Add(UserRightsAssignment.SeBatchLogonRight, new [] { @"DOMAIN\\svc_batch" });

                // reconcile set for a right
                var result = ur.Set(UserRightsAssignment.SeDenyRemoteInteractiveLogonRight,
                    new [] { @"DOMAIN\\contractor1", @"DOMAIN\\contractor2" });
                Console.WriteLine(result);
            }
        }

        public static void ExampleCoversion() {
            string serviceName = "ADSync";
            string serviceExpectedSid = "S-1-5-80-3245704983-3664226991-764670653-2504430226-901976451";
            string serviceSid = NTService.GenerateSID(serviceName);
            Console.WriteLine($"The SID for the service '{serviceName}' is: {serviceSid} {serviceExpectedSid} {(serviceSid == serviceExpectedSid)}");


            string serviceName2 = "MSSQLSERVER";
            string serviceExpectedSid2 = "S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420";
            string serviceSid2 = NTService.GenerateSID(serviceName2);
            Console.WriteLine($"The SID for the service '{serviceName2}' is: {serviceSid2} {serviceExpectedSid2} {(serviceSid2 == serviceExpectedSid2)}");

            string serviceName3 = "himds";
            string serviceExpectedSid3 = "S-1-5-80-4215458991-2034252225-2287069555-1155419622-2701885083";
            string serviceSid3 = NTService.GenerateSID(serviceName3);
            Console.WriteLine($"The SID for the service '{serviceName3}' is: {serviceSid3} {serviceExpectedSid3} {(serviceSid3 == serviceExpectedSid3)}");

            string serviceName4 = "SQLSERVERAGENT";
            string serviceExpectedSid4 = "S-1-5-80-344959196-2060754871-2302487193-2804545603-1466107430";
            string serviceSid4 = NTService.GenerateSID(serviceName4);
            Console.WriteLine($"The SID for the service '{serviceName4}' is: {serviceSid4} {serviceExpectedSid4} {(serviceSid4 == serviceExpectedSid4)}");

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
