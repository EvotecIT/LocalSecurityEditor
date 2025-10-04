# LocalSecurityEditor - .NET Library

[![NuGet Version](https://img.shields.io/nuget/v/LocalSecurityEditor)](https://www.nuget.org/packages/LocalSecurityEditor)
[![NuGet Downloads](https://img.shields.io/nuget/dt/LocalSecurityEditor)](https://www.nuget.org/packages/LocalSecurityEditor)
![.NET Framework 4.7.2](https://img.shields.io/badge/.NET%20Framework-4.7.2-512BD4)
![.NET Standard 2.0](https://img.shields.io/badge/.NET%20Standard-2.0-512BD4)
![.NET (Windows) 8.0 | 9.0](https://img.shields.io/badge/.NET%20(Windows)-8.0%20%7C%209.0-512BD4)
![Platform Windows-only](https://img.shields.io/badge/Platform-Windows--only-blue)

.NET library for managing local security policy (User Rights Assignment). This library powers PowerShell module scenarios and general .NET automation for querying and modifying User Rights Assignments (LSA policy).


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

### Example Local Computer (LSA wrapper)

```csharp
using System;
using LocalSecurityEditor;

namespace TestApp {
    internal class Program {
        static void Main() {
            string[] accounts;

            Console.WriteLine("[*] Displaying current assignments (local)");

            using (LsaWrapper lsa = new LsaWrapper()) {
                accounts = lsa.GetPrivileges(UserRightsAssignment.SeBatchLogonRight);
            }

            foreach (var account in accounts) {
                Console.WriteLine(account);
            }

            Console.WriteLine("[*] Granting right to an account");

            using (LsaWrapper lsa = new LsaWrapper()) {
                lsa.AddPrivileges("EVOTEC\\przemyslaw.klys", UserRightsAssignment.SeBatchLogonRight);
            }

            Console.WriteLine("[*] Displaying current assignments (local)");

            using (LsaWrapper lsa = new LsaWrapper()) {
                accounts = lsa.GetPrivileges(UserRightsAssignment.SeBatchLogonRight);
            }

            foreach (var account in accounts) {
                Console.WriteLine(account);
            }

            Console.WriteLine("[*] Removing a principal and listing again");

            using (LsaWrapper lsa = new LsaWrapper()) {
                lsa.RemovePrivileges("EVOTEC\\przemyslaw.klys", UserRightsAssignment.SeBatchLogonRight);
            }

            using (LsaWrapper lsa = new LsaWrapper()) {
                accounts = lsa.GetPrivileges(UserRightsAssignment.SeBatchLogonRight);
            }

            foreach (var account in accounts) {
                Console.WriteLine(account);
            }
        }
    }
}
```

### Example Remote Computer (LSA wrapper)

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

            Console.WriteLine("[*] Granting right to an account");

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

            Console.WriteLine("[*] Removing the principal and listing again");

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

### Typed, OO API

```csharp
using LocalSecurityEditor;

// Enumerate all rights (local)
var all = UserRights.Get();
foreach (var ura in all) {
    Console.WriteLine($"{ura.ShortName}: {ura.Count} principals");
}

// Lazy streaming
foreach (var ura in new UserRights().EnumerateLazy()) {
    Console.WriteLine(ura);
}

// Single right as typed object with principals
var svc = UserRightsAssignment.SeServiceLogonRight.Get();
foreach (var p in svc.Principals) {
    Console.WriteLine($"{p.AccountName} -> {p.SidString}");
}

// Remote machine catalog
var allRemote = UserRights.Get("SERVER01");

// Add/Remove/Set via fluent extensions
UserRightsAssignment.SeBatchLogonRight.Add(@"DOMAIN\\svc_batch");
UserRightsAssignment.SeBatchLogonRight.Remove(@"DOMAIN\\old_user");
var result = UserRightsAssignment.SeDenyRemoteInteractiveLogonRight.Set(new[]{ @"DOMAIN\\contractor1", @"DOMAIN\\contractor2"});
Console.WriteLine(result); // e.g., SeDenyRemoteInteractiveLogonRight: +1 -0

// Batching with a manager (remote)
using (var ur = new UserRights("SERVER01")) {
    ur.Add(UserRightsAssignment.SeBatchLogonRight, new [] { @"DOMAIN\\svc_batch" });
    var summary = ur.Set(UserRightsAssignment.SeServiceLogonRight, new [] { @"DOMAIN\\svc_svc" });
    Console.WriteLine(summary);
}

```

### Async APIs

```csharp
// Single right (local)
var svc = await new UserRights().GetStateAsync(UserRightsAssignment.SeServiceLogonRight, ct);

// Enumerate all (remote)
var all = await new UserRights("SERVER01").EnumerateAsync(ct);

// Fluent async extensions
var svc2 = await UserRightsAssignment.SeServiceLogonRight.GetAsync("SERVER01", ct);
```

### Thread Safety

- The library is safe to use from multiple tasks.
- Internally it uses a reader–writer lock:
  - Reads may run in parallel; writes are exclusive; dispose is exclusive.
- Prefer reusing a single `UserRights` instance for batching, or create per-task instances for isolation.

### Generate service SIDs

```csharp
string serviceName = "ADSync";
string serviceExpectedSid = "S-1-5-80-3245704983-3664226991-764670653-2504430226-901976451";
string serviceSid = NTService.GenerateSID(serviceName);
Console.WriteLine($"The SID for the service '{serviceName}' is: {serviceSid} {serviceExpectedSid} {(serviceSid == serviceExpectedSid)}");
```
