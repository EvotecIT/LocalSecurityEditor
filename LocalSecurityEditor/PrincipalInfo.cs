using System;
using System.Security.Principal;
using System.Threading;
#if NET5_0_OR_GREATER
using System.Runtime.Versioning;
#endif

namespace LocalSecurityEditor {
    /// <summary>
    /// Represents an account principal with both SID and (optionally) domain-qualified name.
    /// </summary>
    public sealed class PrincipalInfo {
        /// <summary>
        /// String representation of the account's SID (e.g. <c>S-1-5-21-...</c>).
        /// </summary>
        public string SidString { get; }

        /// <summary>
        /// Domain of the account when available (e.g. <c>CONTOSO</c> or <c>BUILTIN</c>).
        /// </summary>
        public string Domain { get; }

        /// <summary>
        /// Account name without domain qualification.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// Classification of the SID as resolved by Windows (user, group, alias, etc.).
        /// </summary>
        public SidNameUse Use { get; }

        /// <summary>
        /// Fully qualified account name in <c>DOMAIN\\Name</c> form when the domain is known; otherwise just <see cref="Name"/>.
        /// </summary>
        public string AccountName =>
            string.IsNullOrEmpty(Domain) ? (Name ?? string.Empty) : ($"{Domain}\\{Name}");

        private SecurityIdentifier _sid;
        /// <summary>
        /// Strongly-typed <see cref="SecurityIdentifier"/> created lazily from <see cref="SidString"/>.
        /// </summary>
        public SecurityIdentifier Sid {
            get {
                var sid = _sid;
                if (sid == null) {
                    var created = new SecurityIdentifier(SidString);
                    Interlocked.CompareExchange(ref _sid, created, null);
                    sid = _sid;
                }
                return sid;
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="PrincipalInfo"/>.
        /// </summary>
        /// <param name="sidString">String SID of the principal.</param>
        /// <param name="domain">Domain name or <c>null</c>.</param>
        /// <param name="name">Account name or <c>null</c>.</param>
        /// <param name="use">SID classification.</param>
        public PrincipalInfo(string sidString, string domain, string name, SidNameUse use) {
            SidString = sidString ?? string.Empty;
            Domain = domain;
            Name = name;
            Use = use;
        }

        /// <summary>
        /// Returns a human-friendly representation containing the account name (when available) and SID.
        /// </summary>
        public override string ToString() =>
            string.IsNullOrEmpty(AccountName) ? SidString : $"{AccountName} ({SidString})";
    }
}
