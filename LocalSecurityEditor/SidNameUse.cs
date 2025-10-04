

namespace LocalSecurityEditor {
    /// <summary>
    /// Mirrors the Windows SID_NAME_USE classification.
    /// </summary>
    public enum SidNameUse : int {
        /// <summary>User account.</summary>
        User = 1,
        /// <summary>Group account.</summary>
        Group = 2,
        /// <summary>Domain SID.</summary>
        Domain = 3,
        /// <summary>Alias or local group.</summary>
        Alias = 4,
        /// <summary>Well-known built-in group.</summary>
        KnownGroup = 5,
        /// <summary>Deleted account.</summary>
        DeletedAccount = 6,
        /// <summary>Invalid SID.</summary>
        Invalid = 7,
        /// <summary>Unknown SID type.</summary>
        Unknown = 8,
        /// <summary>Computer account.</summary>
        Computer = 9
    }
}
