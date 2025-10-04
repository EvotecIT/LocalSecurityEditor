using System;
using System.Collections.Generic;
using System.Linq;

namespace LocalSecurityEditor {
    /// <summary>
    /// Convenience extensions for querying and modifying User Rights using
    /// the <see cref="UserRights"/> facade with a fluent syntax.
    /// </summary>
    public static class UserRightsAssignmentExtensions {
        /// <summary>
        /// Gets the current state for a specific right.
        /// </summary>
        public static UserRightState Get(this UserRightsAssignment right, string systemName = null) {
            using (var mgr = new UserRights(systemName)) {
                return mgr.GetState(right);
            }
        }

        /// <summary>
        /// Grants the specified right to a principal.
        /// </summary>
        public static void Add(this UserRightsAssignment right, string principal, string systemName = null) {
            using (var mgr = new UserRights(systemName)) {
                mgr.Add(right, principal);
            }
        }

        /// <summary>
        /// Grants the specified right to a sequence of principals.
        /// </summary>
        public static void Add(this UserRightsAssignment right, IEnumerable<string> principals, string systemName = null) {
            using (var mgr = new UserRights(systemName)) {
                mgr.Add(right, principals);
            }
        }

        /// <summary>
        /// Removes the specified right from a principal.
        /// </summary>
        public static void Remove(this UserRightsAssignment right, string principal, string systemName = null) {
            using (var mgr = new UserRights(systemName)) {
                mgr.Remove(right, principal);
            }
        }

        /// <summary>
        /// Removes the specified right from a sequence of principals.
        /// </summary>
        public static void Remove(this UserRightsAssignment right, IEnumerable<string> principals, string systemName = null) {
            using (var mgr = new UserRights(systemName)) {
                mgr.Remove(right, principals);
            }
        }

        /// <summary>
        /// Reconciles the right so that exactly the provided principals remain, returning a summary of changes.
        /// </summary>
        public static UserRightSetResult Set(this UserRightsAssignment right, IEnumerable<string> principals, string systemName = null) {
            using (var mgr = new UserRights(systemName)) {
                return mgr.Set(right, principals);
            }
        }
    }
}
