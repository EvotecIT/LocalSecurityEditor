# LocalSecurityEditor - .NET Library

<p align="center">
  <a href="https://www.nuget.org/packages/LocalSecurityEditor"><img alt="Nuget" src="https://img.shields.io/nuget/dt/LocalSecurityEditor?label=nuget%20downloads"></a>
  <a href="https://www.nuget.org/packages/LocalSecurityEditor"><img alt="Nuget" src="https://img.shields.io/nuget/v/LocalSecurityEditor"></a>
  <a href="#"><img src="https://img.shields.io/badge/.NET%20Framework-%3E%3D%204.5-red.svg"></a>
  <a href="#"><img src="https://img.shields.io/badge/.NET%20Standard-%3E%3D%202.0-red.svg"></a>
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

### Supported User Rights Assignement

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

### Credits

- Willy Denoyette [MVP]
- https://www.codeproject.com/Articles/4863/LSA-Functions-Privileges-and-Impersonation
- https://social.msdn.microsoft.com/Forums/lync/en-US/3c0e7d5c-a786-45a1-aa65-a4a2a934c0cb/how-to-access-local-security-policy-of-computer-using-c-?forum=csharpgeneral
- https://web.archive.org/web/20161006162851/http://www.lshift.net/blog/2013/03/25/programmatically-updating-local-policy-in-windows/