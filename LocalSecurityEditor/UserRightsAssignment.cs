namespace LocalSecurityEditor {
    /// <summary>
    /// List of constants used for UserRightsAssignment
    /// Each user right has a constant name and a Group Policy name associated with it.
    /// The constant names are used when referring to the user right in log events.
    /// </summary>
    public enum UserRightsAssignment {
        SeTrustedCredManAccessPrivilege,
        SeNetworkLogonRight,
        SeTcbPrivilege,
        SeMachineAccountPrivilege,
        SeIncreaseQuotaPrivilege,
        SeInteractiveLogonRight,
        SeRemoteInteractiveLogonRight,
        SeBackupPrivilege,
        SeChangeNotifyPrivilege,
        SeSystemtimePrivilege,
        SeTimeZonePrivilege,
        SeCreatePagefilePrivilege,
        SeCreateTokenPrivilege,
        SeCreateGlobalPrivilege,
        SeCreatePermanentPrivilege,
        SeCreateSymbolicLinkPrivilege,
        SeDebugPrivilege,
        SeDenyNetworkLogonRight,
        SeDenyBatchLogonRight,
        SeDenyServiceLogonRight,
        SeDenyInteractiveLogonRight,
        SeDenyRemoteInteractiveLogonRight,
        SeEnableDelegationPrivilege,
        SeRemoteShutdownPrivilege,
        SeAuditPrivilege,
        SeImpersonatePrivilege,
        SeIncreaseWorkingSetPrivilege,
        SeIncreaseBasePriorityPrivilege,
        SeLoadDriverPrivilege,
        SeLockMemoryPrivilege,
        SeBatchLogonRight,
        SeServiceLogonRight,
        SeSecurityPrivilege,
        SeRelabelPrivilege,
        SeSystemEnvironmentPrivilege,
        SeDelegateSessionUserImpersonatePrivilege,
        SeManageVolumePrivilege,
        SeProfileSingleProcessPrivilege,
        SeSystemProfilePrivilege,
        SeUndockPrivilege,
        SeAssignPrimaryTokenPrivilege,
        SeRestorePrivilege,
        SeShutdownPrivilege,
        SeSyncAgentPrivilege,
        SeTakeOwnershipPrivilege
    }
}
