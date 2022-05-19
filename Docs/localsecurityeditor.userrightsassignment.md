# UserRightsAssignment

Namespace: LocalSecurityEditor

List of constants used for UserRightsAssignment
 Each user right has a constant name and a Group Policy name associated with it.
 The constant names are used when referring to the user right in log events.

```csharp
public enum UserRightsAssignment
```

Inheritance [Object](https://docs.microsoft.com/en-us/dotnet/api/system.object) → [ValueType](https://docs.microsoft.com/en-us/dotnet/api/system.valuetype) → [Enum](https://docs.microsoft.com/en-us/dotnet/api/system.enum) → [UserRightsAssignment](./localsecurityeditor.userrightsassignment.md)<br>
Implements [IComparable](https://docs.microsoft.com/en-us/dotnet/api/system.icomparable), [IFormattable](https://docs.microsoft.com/en-us/dotnet/api/system.iformattable), [IConvertible](https://docs.microsoft.com/en-us/dotnet/api/system.iconvertible)

## Fields

| Name | Value | Description |
| --- | --: | --- |
| SeTrustedCredManAccessPrivilege | 0 | Access Credential Manager as a trusted caller |
| SeNetworkLogonRight | 1 | Access this computer from the network |
| SeTcbPrivilege | 2 | Act as part of the operating system |
| SeMachineAccountPrivilege | 3 | Add workstations to domain |
| SeIncreaseQuotaPrivilege | 4 | Adjust memory quotas for a process |
| SeInteractiveLogonRight | 5 | Allow log on locally |
| SeRemoteInteractiveLogonRight | 6 | Allow log on through Remote Desktop Services |
| SeBackupPrivilege | 7 | Back up files and directories |
| SeChangeNotifyPrivilege | 8 | Bypass traverse checking |
| SeSystemtimePrivilege | 9 | Change the system time |
| SeTimeZonePrivilege | 10 | Change the time zone |
| SeCreatePagefilePrivilege | 11 | Create a pagefile |
| SeCreateTokenPrivilege | 12 | Create a token object |
| SeCreateGlobalPrivilege | 13 | Create global objects |
| SeCreatePermanentPrivilege | 14 | Create permanent shared objects |
| SeCreateSymbolicLinkPrivilege | 15 | Create symbolic links |
| SeDebugPrivilege | 16 | Debug programs |
| SeDenyNetworkLogonRight | 17 | Deny access this computer from the network |
| SeDenyBatchLogonRight | 18 | Deny log on as a batch job |
| SeDenyServiceLogonRight | 19 | Deny log on as a service |
| SeDenyInteractiveLogonRight | 20 | Deny log on locally |
| SeDenyRemoteInteractiveLogonRight | 21 | Deny log on through Remote Desktop Services |
| SeEnableDelegationPrivilege | 22 | Enable computer and user accounts to be trusted for delegation |
| SeRemoteShutdownPrivilege | 23 | Force shutdown from a remote system |
| SeAuditPrivilege | 24 | Generate security audits |
| SeImpersonatePrivilege | 25 | Impersonate a client after authentication |
| SeIncreaseWorkingSetPrivilege | 26 | Increase a process working set |
| SeIncreaseBasePriorityPrivilege | 27 | Increase scheduling priority |
| SeLoadDriverPrivilege | 28 | Load and unload device drivers |
| SeLockMemoryPrivilege | 29 | Lock pages in memory |
| SeBatchLogonRight | 30 | Log on as a batch job |
| SeServiceLogonRight | 31 | Log on as a service |
| SeSecurityPrivilege | 32 | Manage auditing and security log |
| SeRelabelPrivilege | 33 | Modify an object label |
| SeSystemEnvironmentPrivilege | 34 | Modify firmware environment values |
| SeManageVolumePrivilege | 35 | Perform volume maintenance tasks |
| SeProfileSingleProcessPrivilege | 36 | Profile single process |
| SeSystemProfilePrivilege | 37 | Profile system performance |
| SeUndockPrivilege | 38 | Remove computer from docking station |
| SeAssignPrimaryTokenPrivilege | 39 | Replace a process level token |
| SeRestorePrivilege | 40 | Restore files and directories |
| SeShutdownPrivilege | 41 | Shut down the system |
| SeSyncAgentPrivilege | 42 | Synchronize directory service data |
| SeTakeOwnershipPrivilege | 43 | Take ownership of files or other objects |
| SeDelegateSessionUserImpersonatePrivilege | 44 | Obtain an impersonation token for another user in the same session |
