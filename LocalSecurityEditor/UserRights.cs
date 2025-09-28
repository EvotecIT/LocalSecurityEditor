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

        public string SystemName { get; }

        public UserRights(string systemName = null) {
            SystemName = systemName;
            _lsa = systemName == null ? new LsaWrapper() : new LsaWrapper(systemName);
        }

        // Static overloads for simple, discoverable Get() usage
        public static IReadOnlyList<UserRightState> Get() {
            using (var ur = new UserRights()) { return ur.Enumerate(); }
        }

        public static IReadOnlyList<UserRightState> Get(string systemName) {
            using (var ur = new UserRights(systemName)) { return ur.Enumerate(); }
        }

        // Single-right static getters intentionally omitted to avoid signature clashes
        // with instance methods. Use the enum extension: right.GetState(systemName).

        public IReadOnlyList<PrincipalInfo> Get(UserRightsAssignment right) { return _lsa.GetPrincipals(right); }

        public UserRightState GetState(UserRightsAssignment right) {
            var def = UserRightsCatalog.GetDefinition(right);
            var principals = _lsa.GetPrincipals(right);
            return new UserRightState(def, principals);
        }

        public IReadOnlyList<UserRightState> Enumerate() {
            var rights = (UserRightsAssignment[])Enum.GetValues(typeof(UserRightsAssignment));
            var list = new List<UserRightState>(rights.Length);
            for (int i = 0; i < rights.Length; i++) {
                list.Add(GetState(rights[i]));
            }
            return list;
        }

        public Dictionary<UserRightsAssignment, UserRightState> GetByRight() {
            var map = new Dictionary<UserRightsAssignment, UserRightState>();
            var rights = (UserRightsAssignment[])Enum.GetValues(typeof(UserRightsAssignment));
            for (int i = 0; i < rights.Length; i++) {
                var right = rights[i];
                map[right] = GetState(right);
            }
            return map;
        }

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

        public void Add(UserRightsAssignment right, IEnumerable<string> principals) {
            foreach (var p in principals) {
                _lsa.AddPrivileges(p, right);
            }
        }

        public void Add(UserRightsAssignment right, params string[] principals) => Add(right, (IEnumerable<string>)principals);

        public void Remove(UserRightsAssignment right, IEnumerable<string> principals) {
            foreach (var p in principals) {
                _lsa.RemovePrivileges(p, right);
            }
        }

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
        public void Add(UserRightsAssignment right, IEnumerable<IdentityReference> principals) {
            foreach (var p in principals) {
                using (var sid = new Win32SecurityIdentifier(p)) {
                    _lsa.AddPrivileges(sid.securityIdentifier.Value, right);
                }
            }
        }

        public void Add(UserRightsAssignment right, IEnumerable<SecurityIdentifier> principals) {
            foreach (var sid in principals) {
                _lsa.AddPrivileges(sid.Value, right);
            }
        }

        public void Remove(UserRightsAssignment right, IEnumerable<IdentityReference> principals) {
            foreach (var p in principals) {
                using (var sid = new Win32SecurityIdentifier(p)) {
                    _lsa.RemovePrivileges(sid.securityIdentifier.Value, right);
                }
            }
        }

        public void Remove(UserRightsAssignment right, IEnumerable<SecurityIdentifier> principals) {
            foreach (var sid in principals) {
                _lsa.RemovePrivileges(sid.Value, right);
            }
        }

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
        public UserRightsAssignment Right { get; }
        public IReadOnlyList<string> Added { get; }
        public IReadOnlyList<string> Removed { get; }
        public bool Changed => (Added.Count + Removed.Count) > 0;

        public UserRightSetResult(UserRightsAssignment right, IEnumerable<string> added, IEnumerable<string> removed) {
            Right = right;
            Added = added.ToArray();
            Removed = removed.ToArray();
        }

        public override string ToString() => $"{Right}: +{Added.Count} -{Removed.Count}";
    }
}
