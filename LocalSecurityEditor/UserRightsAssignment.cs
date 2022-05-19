namespace LocalSecurityEditor {
    /// <summary>
    /// List of constants used for UserRightsAssignment
    /// Each user right has a constant name and a Group Policy name associated with it.
    /// The constant names are used when referring to the user right in log events.
    /// </summary>
    public enum UserRightsAssignment {
        /// <summary>
        /// Access Credential Manager as a trusted caller
        /// </summary>
        SeTrustedCredManAccessPrivilege,
        /// <summary>
        /// Access this computer from the network
        /// </summary>
        SeNetworkLogonRight,
        /// <summary>
        /// Act as part of the operating system
        /// </summary>
        SeTcbPrivilege,
        /// <summary>
        /// Add workstations to domain
        /// </summary>
        SeMachineAccountPrivilege,
        /// <summary>
        /// Adjust memory quotas for a process
        /// </summary>
        SeIncreaseQuotaPrivilege,
        /// <summary>
        /// Allow log on locally
        /// </summary>
        SeInteractiveLogonRight,
        /// <summary>
        /// Allow log on through Remote Desktop Services
        /// </summary>
        SeRemoteInteractiveLogonRight,
        /// <summary>
        /// Back up files and directories
        /// </summary>
        SeBackupPrivilege,
        /// <summary>
        /// Bypass traverse checking
        /// </summary>
        SeChangeNotifyPrivilege,
        /// <summary>
        /// Change the system time
        /// </summary>
        SeSystemtimePrivilege,
        /// <summary>
        /// Change the time zone
        /// </summary>
        SeTimeZonePrivilege,
        /// <summary>
        /// Create a pagefile
        /// </summary>
        SeCreatePagefilePrivilege,
        /// <summary>
        /// Create a token object
        /// </summary>
        SeCreateTokenPrivilege,
        /// <summary>
        /// Create global objects
        /// </summary>
        SeCreateGlobalPrivilege,
        /// <summary>
        /// Create permanent shared objects
        /// </summary>
        SeCreatePermanentPrivilege,
        /// <summary>
        /// Create symbolic links
        /// </summary>
        SeCreateSymbolicLinkPrivilege,
        /// <summary>
        /// Debug programs
        /// </summary>
        SeDebugPrivilege,
        /// <summary>
        /// Deny access this computer from the network
        /// </summary>
        SeDenyNetworkLogonRight,
        /// <summary>
        /// Deny log on as a batch job
        /// </summary>
        SeDenyBatchLogonRight,
        /// <summary>
        /// Deny log on as a service
        /// </summary>
        SeDenyServiceLogonRight,
        /// <summary>
        /// Deny log on locally
        /// </summary>
        SeDenyInteractiveLogonRight,
        /// <summary>
        /// Deny log on through Remote Desktop Services
        /// </summary>
        SeDenyRemoteInteractiveLogonRight,
        /// <summary>
        /// Enable computer and user accounts to be trusted for delegation
        /// </summary>
        SeEnableDelegationPrivilege,
        /// <summary>
        /// Force shutdown from a remote system
        /// </summary>
        SeRemoteShutdownPrivilege,
        /// <summary>
        /// Generate security audits
        /// </summary>
        SeAuditPrivilege,
        /// <summary>
        /// Impersonate a client after authentication
        /// </summary>
        SeImpersonatePrivilege,
        /// <summary>
        /// Increase a process working set
        /// </summary>
        SeIncreaseWorkingSetPrivilege,
        /// <summary>
        /// Increase scheduling priority
        /// </summary>
        SeIncreaseBasePriorityPrivilege,
        /// <summary>
        /// Load and unload device drivers
        /// </summary>
        SeLoadDriverPrivilege,
        /// <summary>
        /// Lock pages in memory
        /// </summary>
        SeLockMemoryPrivilege,
        /// <summary>
        /// Log on as a batch job
        /// </summary>
        SeBatchLogonRight,
        /// <summary>
        /// Log on as a service
        /// </summary>
        SeServiceLogonRight,
        /// <summary>
        /// Manage auditing and security log
        /// </summary>
        SeSecurityPrivilege,
        /// <summary>
        /// Modify an object label
        /// </summary>
        SeRelabelPrivilege,
        /// <summary>
        /// Modify firmware environment values
        /// </summary>
        SeSystemEnvironmentPrivilege,
        /// <summary>
        /// Perform volume maintenance tasks
        /// </summary>
        SeManageVolumePrivilege,
        /// <summary>
        /// Profile single process
        /// </summary>
        SeProfileSingleProcessPrivilege,
        /// <summary>
        /// Profile system performance
        /// </summary>
        SeSystemProfilePrivilege,
        /// <summary>
        /// Remove computer from docking station
        /// </summary>
        SeUndockPrivilege,
        /// <summary>
        /// Replace a process level token
        /// </summary>
        SeAssignPrimaryTokenPrivilege,
        /// <summary>
        /// Restore files and directories
        /// </summary>
        SeRestorePrivilege,
        /// <summary>
        /// Shut down the system
        /// </summary>
        SeShutdownPrivilege,
        /// <summary>
        /// Synchronize directory service data
        /// </summary>
        SeSyncAgentPrivilege,
        /// <summary>
        /// Take ownership of files or other objects
        /// </summary>
        SeTakeOwnershipPrivilege,
        /// <summary>
        /// Obtain an impersonation token for another user in the same session
        /// </summary>
        SeDelegateSessionUserImpersonatePrivilege
    }
}
