# LocalSecurityEditor - .NET Library

.NET library for managing local security policy (User Rights Assignment).


### Supported User Rights Assignment

| ConstantName                              | Group Policy Setting                                               |
| ----------------------------------------- | ------------------------------------------------------------------ |
| SeTrustedCredManAccessPrivilege           | Access Credential Manager as a trusted caller                      |
| SeNetworkLogonRight                       | Access this computer from the network                              |
| SeTcbPrivilege                            | Act as part of the operating system                                |
| SeMachineAccountPrivilege                 | Add workstations to domain                                         |
| SeIncreaseQuotaPrivilege                  | Adjust memory quotas for a process                                 |
| SeInteractiveLogonRight                   | Allow log on locally                                               |
| SeRemoteInteractiveLogonRight             | Allow log on through Remote Desktop Services                       |
| SeBackupPrivilege                         | Back up files and directories                                      |
| SeChangeNotifyPrivilege                   | Bypass traverse checking                                           |
| SeSystemtimePrivilege                     | Change the system time                                             |
| SeTimeZonePrivilege                       | Change the time zone                                               |
| SeCreatePagefilePrivilege                 | Create a pagefile                                                  |
| SeCreateTokenPrivilege                    | Create a token object                                              |
| SeCreateGlobalPrivilege                   | Create global objects                                              |
| SeCreatePermanentPrivilege                | Create permanent shared objects                                    |
| SeCreateSymbolicLinkPrivilege             | Create symbolic links                                              |
| SeDebugPrivilege                          | Debug programs                                                     |
| SeDenyNetworkLogonRight                   | Deny access to this computer from the network                      |
| SeDenyBatchLogonRight                     | Deny log on as a batch job                                         |
| SeDenyServiceLogonRight                   | Deny log on as a service                                           |
| SeDenyInteractiveLogonRight               | Deny log on locally                                                |
| SeDenyRemoteInteractiveLogonRight         | Deny log on through Remote Desktop Services                        |
| SeEnableDelegationPrivilege               | Enable computer and user accounts to be trusted for delegation     |
| SeRemoteShutdownPrivilege                 | Force shutdown from a remote system                                |
| SeAuditPrivilege                          | Generate security audits                                           |
| SeImpersonatePrivilege                    | Impersonate a client after authentication                          |
| SeIncreaseWorkingSetPrivilege             | Increase a process working set                                     |
| SeIncreaseBasePriorityPrivilege           | Increase scheduling priority                                       |
| SeLoadDriverPrivilege                     | Load and unload device drivers                                     |
| SeLockMemoryPrivilege                     | Lock pages in memory                                               |
| SeBatchLogonRight                         | Log on as a batch job                                              |
| SeServiceLogonRight                       | Log on as a service                                                |
| SeSecurityPrivilege                       | Manage auditing and security log                                   |
| SeRelabelPrivilege                        | Modify an object label                                             |
| SeSystemEnvironmentPrivilege              | Modify firmware environment values                                 |
| SeDelegateSessionUserImpersonatePrivilege | Obtain an impersonation token for another user in the same session |
| SeManageVolumePrivilege                   | Perform volume maintenance tasks                                   |
| SeProfileSingleProcessPrivilege           | Profile single process                                             |
| SeSystemProfilePrivilege                  | Profile system performance                                         |
| SeUndockPrivilege                         | Remove computer from docking station                               |
| SeAssignPrimaryTokenPrivilege             | Replace a process level token                                      |
| SeRestorePrivilege                        | Restore files and directories                                      |
| SeShutdownPrivilege                       | Shut down the system                                               |
| SeSyncAgentPrivilege                      | Synchronize directory service data                                 |
| SeTakeOwnershipPrivilege                  | Take ownership of files or other objects                           |

### Example Local Computer

```csharp
using System;
using LocalSecurityEditor;

namespace TestApp {
    internal class Program {
        static void Main() {
            string[] accounts;

            Console.WriteLine("[*] Accessing  server - Displaying Current");

            using (LsaWrapper lsa = new LsaWrapper()) {
                accounts = lsa.GetPrivileges(UserRightsAssignment.SeBatchLogonRight);
            }

            foreach (var account in accounts) {
                Console.WriteLine(account);
            }

            Console.WriteLine("[*] Adding Account to the Server");

            using (LsaWrapper lsa = new LsaWrapper()) {
                lsa.AddPrivileges("EVOTEC\\przemyslaw.klys", UserRightsAssignment.SeBatchLogonRight);
            }

            Console.WriteLine("[*] Accessing  server - Displaying Current");

            using (LsaWrapper lsa = new LsaWrapper()) {
                accounts = lsa.GetPrivileges(UserRightsAssignment.SeBatchLogonRight);
            }

            foreach (var account in accounts) {
                Console.WriteLine(account);
            }

            Console.WriteLine("[*] Accessing  server - Displaying Current");

            using (LsaWrapper lsa = new LsaWrapper()) {
                lsa.RemovePrivileges("EVOTEC\\przemyslaw.klys", UserRightsAssignment.SeBatchLogonRight);
            }

            using (LsaWrapper lsa = new LsaWrapper("")) {
                accounts = lsa.GetPrivileges(UserRightsAssignment.SeBatchLogonRight);
            }

            foreach (var account in accounts) {
                Console.WriteLine(account);
            }
        }
    }
}
```

### Example Remote Computer

```csharp
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
```

### New Typed, OO API (vNext)

```csharp
using LocalSecurityEditor;

// Get all user rights as typed objects (one per right)
var all = UserRights.Get();
foreach (var ura in all)
{
    Console.WriteLine($"{ura.ShortName} -> {ura.Count} principals");
}

// Single right as typed object with principals
var svc = UserRightsAssignment.SeServiceLogonRight.Get();
Console.WriteLine($"{svc.Name}: {string.Join(", ", svc.Principals.Select(p => p.AccountName))}");

// Remote machine catalog
var allRemote = UserRights.Get("SERVER01");

// Add/Remove/Set
UserRightsAssignment.SeBatchLogonRight.Add(@"DOMAIN\\svc_batch");
UserRightsAssignment.SeBatchLogonRight.Remove(@"DOMAIN\\old_user");
var result = UserRightsAssignment.SeDenyRemoteInteractiveLogonRight.Set(new[]{ @"DOMAIN\\contractor1", @"DOMAIN\\contractor2"});
Console.WriteLine(result); // e.g., SeDenyRemoteInteractiveLogonRight: +1 -0
```
