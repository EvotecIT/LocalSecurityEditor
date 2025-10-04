using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
#if NET5_0_OR_GREATER
using System.Runtime.Versioning;
#endif

namespace LocalSecurityEditor {
    /// <summary>
    /// Object-oriented facade for managing User Rights Assignments.
    /// </summary>
#if NET5_0_OR_GREATER
    [SupportedOSPlatform("windows")]
#endif
    public sealed class UserRights : IDisposable {
        private readonly LsaWrapper _lsa;
        private bool _disposed;

        /// <summary>
        /// Target system name this instance operates on, or <c>null</c> for the local machine.
        /// </summary>
        public string SystemName { get; }

        /// <summary>
        /// Creates a manager for the local machine.
        /// </summary>
        public UserRights(string systemName = null) {
            SystemName = systemName;
            _lsa = systemName == null ? new LsaWrapper() : new LsaWrapper(systemName);
        }

        // Static overloads for simple, discoverable Get() usage
        /// <summary>
        /// Enumerates the state of all user rights on the local machine.
        /// </summary>
        /// <returns>Collection of <see cref="UserRightState"/> objects.</returns>
        public static IReadOnlyList<UserRightState> Get() {
            using (var ur = new UserRights()) { return ur.Enumerate(); }
        }

        /// <summary>
        /// Enumerates the state of all user rights on a remote machine.
        /// </summary>
        /// <param name="systemName">Target computer name.</param>
        /// <returns>Collection of <see cref="UserRightState"/> objects.</returns>
        public static IReadOnlyList<UserRightState> Get(string systemName) {
            using (var ur = new UserRights(systemName)) { return ur.Enumerate(); }
        }

        // Single-right static getters intentionally omitted to avoid signature clashes
        // with instance methods. Use the enum extension: right.GetState(systemName).

        /// <summary>
        /// Lists principals assigned to a specific user right.
        /// </summary>
        public IReadOnlyList<PrincipalInfo> Get(UserRightsAssignment right) { return _lsa.GetPrincipals(right); }

        /// <summary>
        /// Gets the full state for a specific user right including metadata and principals.
        /// </summary>
        public UserRightState GetState(UserRightsAssignment right) {
            var def = UserRightsCatalog.GetDefinition(right);
            var principals = _lsa.GetPrincipals(right);
            return new UserRightState(def, principals);
        }

        /// <summary>
        /// Enumerates the state for all user rights.
        /// </summary>
        public IReadOnlyList<UserRightState> Enumerate() {
            var rights = (UserRightsAssignment[])Enum.GetValues(typeof(UserRightsAssignment));
            var list = new List<UserRightState>(rights.Length);
            for (int i = 0; i < rights.Length; i++) {
                list.Add(GetState(rights[i]));
            }
            return list;
        }

        /// <summary>
        /// Returns a map keyed by <see cref="UserRightsAssignment"/> for convenient lookup.
        /// </summary>
        public Dictionary<UserRightsAssignment, UserRightState> GetByRight() {
            var map = new Dictionary<UserRightsAssignment, UserRightState>();
            var rights = (UserRightsAssignment[])Enum.GetValues(typeof(UserRightsAssignment));
            for (int i = 0; i < rights.Length; i++) {
                var right = rights[i];
                map[right] = GetState(right);
            }
            return map;
        }

        /// <summary>
        /// Returns a map keyed by the short name of each right (e.g. <c>SeDebugPrivilege</c>).
        /// </summary>
        public Dictionary<string, UserRightState> GetByShortName(StringComparer comparer = null) {
            if (comparer == null) comparer = StringComparer.Ordinal;
            var map = new Dictionary<string, UserRightState>(comparer);
            var rights = (UserRightsAssignment[])Enum.GetValues(typeof(UserRightsAssignment));
            for (int i = 0; i < rights.Length; i++) {
                var state = GetState(rights[i]);
                map[state.ShortName] = state;
            }
            return map;
        }

        /// <summary>
        /// Grants a right to each of the specified principals.
        /// </summary>
        public void Add(UserRightsAssignment right, IEnumerable<string> principals) {
            foreach (var p in principals) {
                _lsa.AddPrivileges(p, right);
            }
        }

        /// <summary>
        /// Grants a right to one or more principals.
        /// </summary>
        public void Add(UserRightsAssignment right, params string[] principals) => Add(right, (IEnumerable<string>)principals);

        /// <summary>
        /// Removes a right from each of the specified principals.
        /// </summary>
        public void Remove(UserRightsAssignment right, IEnumerable<string> principals) {
            foreach (var p in principals) {
                _lsa.RemovePrivileges(p, right);
            }
        }

        /// <summary>
        /// Removes a right from one or more principals.
        /// </summary>
        public void Remove(UserRightsAssignment right, params string[] principals) => Remove(right, (IEnumerable<string>)principals);

        /// <summary>
        /// Sets the exact principal set for a given right. Adds missing entries and removes extras.
        /// Returns a summary of changes performed.
        /// </summary>
        public UserRightSetResult Set(UserRightsAssignment right, IEnumerable<string> desiredPrincipals) {
            var existing = Get(right);
            var existingSids = new HashSet<string>(existing.Select(e => e.SidString), StringComparer.OrdinalIgnoreCase);

            var desiredSidSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var principal in desiredPrincipals) {
                using (var sid = new Win32SecurityIdentifier(principal)) {
                    desiredSidSet.Add(sid.securityIdentifier.Value);
                }
            }

            var toAdd = desiredSidSet.Except(existingSids).ToArray();
            var toRemove = existingSids.Except(desiredSidSet).ToArray();

            foreach (var sid in toAdd) {
                _lsa.AddPrivileges(sid, right); // accepts SID or account name
            }
            foreach (var sid in toRemove) {
                _lsa.RemovePrivileges(sid, right);
            }

            return new UserRightSetResult(right, added: toAdd, removed: toRemove);
        }

        // Overloads for typed identities
        /// <summary>
        /// Grants a right to a collection of identities (any <see cref="IdentityReference"/>).
        /// </summary>
        public void Add(UserRightsAssignment right, IEnumerable<IdentityReference> principals) {
            foreach (var p in principals) {
                using (var sid = new Win32SecurityIdentifier(p)) {
                    _lsa.AddPrivileges(sid.securityIdentifier.Value, right);
                }
            }
        }

        /// <summary>
        /// Grants a right to a collection of SIDs.
        /// </summary>
        public void Add(UserRightsAssignment right, IEnumerable<SecurityIdentifier> principals) {
            foreach (var sid in principals) {
                _lsa.AddPrivileges(sid.Value, right);
            }
        }

        /// <summary>
        /// Removes a right from a collection of identities (any <see cref="IdentityReference"/>).
        /// </summary>
        public void Remove(UserRightsAssignment right, IEnumerable<IdentityReference> principals) {
            foreach (var p in principals) {
                using (var sid = new Win32SecurityIdentifier(p)) {
                    _lsa.RemovePrivileges(sid.securityIdentifier.Value, right);
                }
            }
        }

        /// <summary>
        /// Removes a right from a collection of SIDs.
        /// </summary>
        public void Remove(UserRightsAssignment right, IEnumerable<SecurityIdentifier> principals) {
            foreach (var sid in principals) {
                _lsa.RemovePrivileges(sid.Value, right);
            }
        }

        /// <summary>
        /// Releases unmanaged resources held by this instance.
        /// </summary>
        public void Dispose() {
            if (_disposed) return;
            _lsa.Dispose();
            _disposed = true;
        }
    }

    /// <summary>
    /// Result summary for Set operation.
    /// </summary>
    public sealed class UserRightSetResult {
        /// <summary>
        /// The right that was reconciled.
        /// </summary>
        public UserRightsAssignment Right { get; }

        /// <summary>
        /// Principals that were granted the right during the operation.
        /// </summary>
        public IReadOnlyList<string> Added { get; }

        /// <summary>
        /// Principals that had the right removed during the operation.
        /// </summary>
        public IReadOnlyList<string> Removed { get; }

        /// <summary>
        /// Indicates whether any changes were made.
        /// </summary>
        public bool Changed => (Added.Count + Removed.Count) > 0;

        /// <summary>
        /// Creates a new result instance.
        /// </summary>
        public UserRightSetResult(UserRightsAssignment right, IEnumerable<string> added, IEnumerable<string> removed) {
            Right = right;
            Added = added.ToArray();
            Removed = removed.ToArray();
        }

        /// <summary>
        /// Returns a concise summary string for diagnostics.
        /// </summary>
        public override string ToString() => $"{Right}: +{Added.Count} -{Removed.Count}";
    }
}
