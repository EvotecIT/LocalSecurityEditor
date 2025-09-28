using System;
using System.Security.Principal;
#if NET5_0_OR_GREATER
using System.Runtime.Versioning;
#endif

namespace LocalSecurityEditor {
    /// <summary>
    /// Represents an account principal with both SID and (optionally) domain-qualified name.
    /// </summary>
#if NET5_0_OR_GREATER
    [SupportedOSPlatform("windows")]
#endif
    public sealed class PrincipalInfo {
        public string SidString { get; }
        public string Domain { get; }
        public string Name { get; }
        public SidNameUse Use { get; }

        public string AccountName =>
            string.IsNullOrEmpty(Domain) ? (Name ?? string.Empty) : ($"{Domain}\\{Name}");

        public SecurityIdentifier Sid => new SecurityIdentifier(SidString);

        public PrincipalInfo(string sidString, string domain, string name, SidNameUse use) {
            SidString = sidString ?? string.Empty;
            Domain = domain;
            Name = name;
            Use = use;
        }

        public override string ToString() =>
            string.IsNullOrEmpty(AccountName) ? SidString : $"{AccountName} ({SidString})";
    }
}
