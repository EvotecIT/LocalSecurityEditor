using System;
using System.Collections.Generic;
using System.Linq;

namespace LocalSecurityEditor {
    internal static class UserRightsCatalog {
        private static readonly Dictionary<UserRightsAssignment, UserRightDefinition> _defs =
            new Dictionary<UserRightsAssignment, UserRightDefinition> {
                { UserRightsAssignment.SeTrustedCredManAccessPrivilege, Def(UserRightsAssignment.SeTrustedCredManAccessPrivilege, "SeTrustedCredManAccessPrivilege", "Access Credential Manager as a trusted caller") },
                { UserRightsAssignment.SeNetworkLogonRight, Def(UserRightsAssignment.SeNetworkLogonRight, "SeNetworkLogonRight", "Access this computer from the network") },
                { UserRightsAssignment.SeTcbPrivilege, Def(UserRightsAssignment.SeTcbPrivilege, "SeTcbPrivilege", "Act as part of the operating system") },
                { UserRightsAssignment.SeMachineAccountPrivilege, Def(UserRightsAssignment.SeMachineAccountPrivilege, "SeMachineAccountPrivilege", "Add workstations to domain") },
                { UserRightsAssignment.SeIncreaseQuotaPrivilege, Def(UserRightsAssignment.SeIncreaseQuotaPrivilege, "SeIncreaseQuotaPrivilege", "Adjust memory quotas for a process") },
                { UserRightsAssignment.SeInteractiveLogonRight, Def(UserRightsAssignment.SeInteractiveLogonRight, "SeInteractiveLogonRight", "Allow log on locally") },
                { UserRightsAssignment.SeRemoteInteractiveLogonRight, Def(UserRightsAssignment.SeRemoteInteractiveLogonRight, "SeRemoteInteractiveLogonRight", "Allow log on through Remote Desktop Services") },
                { UserRightsAssignment.SeBackupPrivilege, Def(UserRightsAssignment.SeBackupPrivilege, "SeBackupPrivilege", "Back up files and directories") },
                { UserRightsAssignment.SeChangeNotifyPrivilege, Def(UserRightsAssignment.SeChangeNotifyPrivilege, "SeChangeNotifyPrivilege", "Bypass traverse checking") },
                { UserRightsAssignment.SeSystemtimePrivilege, Def(UserRightsAssignment.SeSystemtimePrivilege, "SeSystemtimePrivilege", "Change the system time") },
                { UserRightsAssignment.SeTimeZonePrivilege, Def(UserRightsAssignment.SeTimeZonePrivilege, "SeTimeZonePrivilege", "Change the time zone") },
                { UserRightsAssignment.SeCreatePagefilePrivilege, Def(UserRightsAssignment.SeCreatePagefilePrivilege, "SeCreatePagefilePrivilege", "Create a pagefile") },
                { UserRightsAssignment.SeCreateTokenPrivilege, Def(UserRightsAssignment.SeCreateTokenPrivilege, "SeCreateTokenPrivilege", "Create a token object") },
                { UserRightsAssignment.SeCreateGlobalPrivilege, Def(UserRightsAssignment.SeCreateGlobalPrivilege, "SeCreateGlobalPrivilege", "Create global objects") },
                { UserRightsAssignment.SeCreatePermanentPrivilege, Def(UserRightsAssignment.SeCreatePermanentPrivilege, "SeCreatePermanentPrivilege", "Create permanent shared objects") },
                { UserRightsAssignment.SeCreateSymbolicLinkPrivilege, Def(UserRightsAssignment.SeCreateSymbolicLinkPrivilege, "SeCreateSymbolicLinkPrivilege", "Create symbolic links") },
                { UserRightsAssignment.SeDebugPrivilege, Def(UserRightsAssignment.SeDebugPrivilege, "SeDebugPrivilege", "Debug programs") },
                { UserRightsAssignment.SeDenyNetworkLogonRight, Def(UserRightsAssignment.SeDenyNetworkLogonRight, "SeDenyNetworkLogonRight", "Deny access to this computer from the network") },
                { UserRightsAssignment.SeDenyBatchLogonRight, Def(UserRightsAssignment.SeDenyBatchLogonRight, "SeDenyBatchLogonRight", "Deny log on as a batch job") },
                { UserRightsAssignment.SeDenyServiceLogonRight, Def(UserRightsAssignment.SeDenyServiceLogonRight, "SeDenyServiceLogonRight", "Deny log on as a service") },
                { UserRightsAssignment.SeDenyInteractiveLogonRight, Def(UserRightsAssignment.SeDenyInteractiveLogonRight, "SeDenyInteractiveLogonRight", "Deny log on locally") },
                { UserRightsAssignment.SeDenyRemoteInteractiveLogonRight, Def(UserRightsAssignment.SeDenyRemoteInteractiveLogonRight, "SeDenyRemoteInteractiveLogonRight", "Deny log on through Remote Desktop Services") },
                { UserRightsAssignment.SeEnableDelegationPrivilege, Def(UserRightsAssignment.SeEnableDelegationPrivilege, "SeEnableDelegationPrivilege", "Enable accounts to be trusted for delegation") },
                { UserRightsAssignment.SeRemoteShutdownPrivilege, Def(UserRightsAssignment.SeRemoteShutdownPrivilege, "SeRemoteShutdownPrivilege", "Force shutdown from a remote system") },
                { UserRightsAssignment.SeAuditPrivilege, Def(UserRightsAssignment.SeAuditPrivilege, "SeAuditPrivilege", "Generate security audits") },
                { UserRightsAssignment.SeImpersonatePrivilege, Def(UserRightsAssignment.SeImpersonatePrivilege, "SeImpersonatePrivilege", "Impersonate a client after authentication") },
                { UserRightsAssignment.SeIncreaseWorkingSetPrivilege, Def(UserRightsAssignment.SeIncreaseWorkingSetPrivilege, "SeIncreaseWorkingSetPrivilege", "Increase a process working set") },
                { UserRightsAssignment.SeIncreaseBasePriorityPrivilege, Def(UserRightsAssignment.SeIncreaseBasePriorityPrivilege, "SeIncreaseBasePriorityPrivilege", "Increase scheduling priority") },
                { UserRightsAssignment.SeLoadDriverPrivilege, Def(UserRightsAssignment.SeLoadDriverPrivilege, "SeLoadDriverPrivilege", "Load and unload device drivers") },
                { UserRightsAssignment.SeLockMemoryPrivilege, Def(UserRightsAssignment.SeLockMemoryPrivilege, "SeLockMemoryPrivilege", "Lock pages in memory") },
                { UserRightsAssignment.SeBatchLogonRight, Def(UserRightsAssignment.SeBatchLogonRight, "SeBatchLogonRight", "Log on as a batch job") },
                { UserRightsAssignment.SeServiceLogonRight, Def(UserRightsAssignment.SeServiceLogonRight, "SeServiceLogonRight", "Log on as a service") },
                { UserRightsAssignment.SeSecurityPrivilege, Def(UserRightsAssignment.SeSecurityPrivilege, "SeSecurityPrivilege", "Manage auditing and security log") },
                { UserRightsAssignment.SeRelabelPrivilege, Def(UserRightsAssignment.SeRelabelPrivilege, "SeRelabelPrivilege", "Modify an object label") },
                { UserRightsAssignment.SeSystemEnvironmentPrivilege, Def(UserRightsAssignment.SeSystemEnvironmentPrivilege, "SeSystemEnvironmentPrivilege", "Modify firmware environment values") },
                { UserRightsAssignment.SeManageVolumePrivilege, Def(UserRightsAssignment.SeManageVolumePrivilege, "SeManageVolumePrivilege", "Perform volume maintenance tasks") },
                { UserRightsAssignment.SeProfileSingleProcessPrivilege, Def(UserRightsAssignment.SeProfileSingleProcessPrivilege, "SeProfileSingleProcessPrivilege", "Profile single process") },
                { UserRightsAssignment.SeSystemProfilePrivilege, Def(UserRightsAssignment.SeSystemProfilePrivilege, "SeSystemProfilePrivilege", "Profile system performance") },
                { UserRightsAssignment.SeUndockPrivilege, Def(UserRightsAssignment.SeUndockPrivilege, "SeUndockPrivilege", "Remove computer from docking station") },
                { UserRightsAssignment.SeAssignPrimaryTokenPrivilege, Def(UserRightsAssignment.SeAssignPrimaryTokenPrivilege, "SeAssignPrimaryTokenPrivilege", "Replace a process level token") },
                { UserRightsAssignment.SeRestorePrivilege, Def(UserRightsAssignment.SeRestorePrivilege, "SeRestorePrivilege", "Restore files and directories") },
                { UserRightsAssignment.SeShutdownPrivilege, Def(UserRightsAssignment.SeShutdownPrivilege, "SeShutdownPrivilege", "Shut down the system") },
                { UserRightsAssignment.SeSyncAgentPrivilege, Def(UserRightsAssignment.SeSyncAgentPrivilege, "SeSyncAgentPrivilege", "Synchronize directory service data") },
                { UserRightsAssignment.SeTakeOwnershipPrivilege, Def(UserRightsAssignment.SeTakeOwnershipPrivilege, "SeTakeOwnershipPrivilege", "Take ownership of files or other objects") },
                { UserRightsAssignment.SeDelegateSessionUserImpersonatePrivilege, Def(UserRightsAssignment.SeDelegateSessionUserImpersonatePrivilege, "SeDelegateSessionUserImpersonatePrivilege", "Obtain an impersonation token for another user in the same session") },
            };

        private static UserRightDefinition Def(UserRightsAssignment r, string shortName, string name) {
            // For now, Description mirrors the friendly name. Can be expanded later.
            return new UserRightDefinition(r, shortName, name, name);
        }

        internal static UserRightDefinition GetDefinition(UserRightsAssignment right) { return _defs[right]; }
        internal static IReadOnlyList<UserRightDefinition> GetAllDefinitions() { return _defs.Values.ToArray(); }
        internal static int Count { get { return _defs.Count; } }
    }
}

