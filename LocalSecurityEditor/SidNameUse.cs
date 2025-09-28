using System;
#if NET5_0_OR_GREATER
using System.Runtime.Versioning;
#endif

namespace LocalSecurityEditor {
    /// <summary>
    /// Mirrors the Windows SID_NAME_USE classification.
    /// </summary>
#if NET5_0_OR_GREATER
    [SupportedOSPlatform("windows")]
#endif
    public enum SidNameUse : int {
        User = 1,
        Group = 2,
        Domain = 3,
        Alias = 4,
        KnownGroup = 5,
        DeletedAccount = 6,
        Invalid = 7,
        Unknown = 8,
        Computer = 9
    }
}

