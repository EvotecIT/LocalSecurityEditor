# LocalSecurityEditor - .NET Library

<p align="center">
  <a href="https://www.nuget.org/packages/LocalSecurityEditor"><img alt="Nuget" src="https://img.shields.io/nuget/dt/LocalSecurityEditor?label=nuget%20downloads"></a>
  <a href="https://www.nuget.org/packages/LocalSecurityEditor"><img alt="Nuget" src="https://img.shields.io/nuget/v/LocalSecurityEditor"></a>
  <a href="#"><img src="https://img.shields.io/badge/targets-net472%20|%20netstandard2.0%20|%20net8.0--windows%20|%20net9.0--windows-blue"></a>
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/github/license/EvotecIT/LocalSecurityEditor.svg"></a>
  <a href="#"><img src="https://img.shields.io/github/languages/top/evotecit/LocalSecurityEditor.svg"></a>
  <a href="#"><img src="https://img.shields.io/github/languages/code-size/evotecit/LocalSecurityEditor.svg"></a>
</p>

<p align="center">
  <a href="https://twitter.com/PrzemyslawKlys"><img src="https://img.shields.io/twitter/follow/PrzemyslawKlys.svg?label=Twitter%20%40PrzemyslawKlys&style=social"></a>
  <a href="https://evotec.xyz/hub"><img src="https://img.shields.io/badge/Blog-evotec.xyz-2A6496.svg"></a>
  <a href="https://www.linkedin.com/in/pklys"><img src="https://img.shields.io/badge/LinkedIn-pklys-0077B5.svg?logo=LinkedIn"></a>
</p>

## Description

.NET library for managing local security policy (User Rights Assignment). This library was written to use in PowerShell Module [SecurityPolicy](https://github.com/EvotecIT/SecurityPolicy) providing easy way to manage local security policy.

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

### Example GenerateSID

```csharp
string serviceName = "ADSync";
string serviceExpectedSid = "S-1-5-80-3245704983-3664226991-764670653-2504430226-901976451";
string serviceSid = NTService.GenerateSID(serviceName);
Console.WriteLine($"The SID for the service '{serviceName}' is: {serviceSid} {serviceExpectedSid} {(serviceSid == serviceExpectedSid)}");
```

### Typed, OO API

```csharp
using LocalSecurityEditor;

// Get state for a right (local machine)
var svc = UserRightsAssignment.SeServiceLogonRight.Get();
foreach (var p in svc.Principals) {
    Console.WriteLine($"{p.AccountName} -> {p.SidString}");
}

// Manage rights on a remote system (batching via manager)
using (var ur = new UserRights("SERVER01")) {
    // Add by account name or SID
    ur.Add(UserRightsAssignment.SeBatchLogonRight, new [] { @"DOMAIN\\svc_batch", "S-1-5-32-544" });

    // Replace entire set for a right (adds missing, removes extras)
    var result = ur.Set(UserRightsAssignment.SeDenyRemoteInteractiveLogonRight,
        new [] { @"DOMAIN\\contractor1", @"DOMAIN\\contractor2" });
    Console.WriteLine(result); // e.g., SeDenyRemoteInteractiveLogonRight: +1 -0
}

// Performance tip: For many operations, prefer reusing a single UserRights instance
// Less efficient (allocates per call):
// right.Add("user1"); right.Add("user2"); right.Add("user3");
// Better:
// using var ur = new UserRights();
// ur.Add(right, new [] { "user1", "user2", "user3" });

### Async APIs

// Query a single right asynchronously (local)
var state = await new UserRights().GetStateAsync(UserRightsAssignment.SeServiceLogonRight, ct);

// Enumerate all rights asynchronously (remote)
var all = await new UserRights("SERVER01").EnumerateAsync(ct);

// Grant/remove asynchronously
await new UserRights().AddAsync(UserRightsAssignment.SeBatchLogonRight, new[] { @"DOMAIN\\user1" }, ct);
await new UserRights().RemoveAsync(UserRightsAssignment.SeBatchLogonRight, new[] { @"DOMAIN\\user1" }, ct);

// Fluent async extensions
var svc = await UserRightsAssignment.SeServiceLogonRight.GetAsync("SERVER01", ct);

### Aggregate URA Objects (PowerShell-friendly)

```csharp
// One object per user right, each with Principals[]
var all = UserRights.Get(); // static Get() overload — local machine
// or as dictionary keyed by enum
var byRight = new UserRights().GetByRight(); // instance when batching
// or keyed by ShortName (e.g., "SeServiceLogonRight")
var byShort = new UserRights().GetByShortName();

// Single right as typed object
var single = UserRightsAssignment.SeServiceLogonRight.Get(); // single right via extension
Console.WriteLine($"{single.Name} has {single.Count} principals");
```
```

### Credits

This library was created based on help from mutliple sources. Without those, it wouldn't be possible.

- Willy Denoyette [MVP]
- [LSA Functions - Privileges and Impersonation](https://www.codeproject.com/Articles/4863/LSA-Functions-Privileges-and-Impersonation)
- [How to access local security policy of computer using C#](https://social.msdn.microsoft.com/Forums/lync/en-US/3c0e7d5c-a786-45a1-aa65-a4a2a934c0cb/how-to-access-local-security-policy-of-computer-using-c-?forum=csharpgeneral)
- [Programmatically updating local policy in Windows](https://web.archive.org/web/20161006162851/http://www.lshift.net/blog/2013/03/25/programmatically-updating-local-policy-in-windows/)
