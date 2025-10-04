using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

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
        /// Asynchronously gets the current state for a specific right.
        /// </summary>
        public static Task<UserRightState> GetAsync(this UserRightsAssignment right, string systemName = null, CancellationToken cancellationToken = default) {
            using (var mgr = new UserRights(systemName)) {
                return mgr.GetStateAsync(right, cancellationToken);
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
        /// Asynchronously grants the specified right to a principal.
        /// </summary>
        public static Task AddAsync(this UserRightsAssignment right, string principal, string systemName = null, CancellationToken cancellationToken = default) {
            using (var mgr = new UserRights(systemName)) {
                return mgr.AddAsync(right, new [] { principal }, cancellationToken);
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
        /// Asynchronously grants the specified right to a sequence of principals.
        /// </summary>
        public static Task AddAsync(this UserRightsAssignment right, IEnumerable<string> principals, string systemName = null, CancellationToken cancellationToken = default) {
            using (var mgr = new UserRights(systemName)) {
                return mgr.AddAsync(right, principals, cancellationToken);
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
        /// Asynchronously removes the specified right from a principal.
        /// </summary>
        public static Task RemoveAsync(this UserRightsAssignment right, string principal, string systemName = null, CancellationToken cancellationToken = default) {
            using (var mgr = new UserRights(systemName)) {
                return mgr.RemoveAsync(right, new [] { principal }, cancellationToken);
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
        /// Asynchronously removes the specified right from a sequence of principals.
        /// </summary>
        public static Task RemoveAsync(this UserRightsAssignment right, IEnumerable<string> principals, string systemName = null, CancellationToken cancellationToken = default) {
            using (var mgr = new UserRights(systemName)) {
                return mgr.RemoveAsync(right, principals, cancellationToken);
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

        /// <summary>
        /// Asynchronously reconciles the right so that exactly the provided principals remain.
        /// </summary>
        public static Task<UserRightSetResult> SetAsync(this UserRightsAssignment right, IEnumerable<string> principals, string systemName = null, CancellationToken cancellationToken = default) {
            using (var mgr = new UserRights(systemName)) {
                return mgr.SetAsync(right, principals, cancellationToken);
            }
        }
    }
}
