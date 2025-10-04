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
        /// Note: creates a short-lived <see cref="UserRights"/>; for many calls prefer reusing an instance.
        /// </summary>
        public static async Task<UserRightState> GetAsync(this UserRightsAssignment right, string systemName = null, CancellationToken cancellationToken = default) {
            using (var mgr = new UserRights(systemName)) {
                return await mgr.GetStateAsync(right, cancellationToken).ConfigureAwait(false);
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
        public static async Task AddAsync(this UserRightsAssignment right, string principal, string systemName = null, CancellationToken cancellationToken = default) {
            using (var mgr = new UserRights(systemName)) {
                await mgr.AddAsync(right, new [] { principal }, cancellationToken).ConfigureAwait(false);
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
        public static async Task AddAsync(this UserRightsAssignment right, IEnumerable<string> principals, string systemName = null, CancellationToken cancellationToken = default) {
            using (var mgr = new UserRights(systemName)) {
                await mgr.AddAsync(right, principals, cancellationToken).ConfigureAwait(false);
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
        public static async Task RemoveAsync(this UserRightsAssignment right, string principal, string systemName = null, CancellationToken cancellationToken = default) {
            using (var mgr = new UserRights(systemName)) {
                await mgr.RemoveAsync(right, new [] { principal }, cancellationToken).ConfigureAwait(false);
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
        public static async Task RemoveAsync(this UserRightsAssignment right, IEnumerable<string> principals, string systemName = null, CancellationToken cancellationToken = default) {
            using (var mgr = new UserRights(systemName)) {
                await mgr.RemoveAsync(right, principals, cancellationToken).ConfigureAwait(false);
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
        /// Reconciles the right using an existing manager instance (more efficient for bulk operations).
        /// </summary>
        public static UserRightSetResult Set(this UserRightsAssignment right, UserRights manager, IEnumerable<string> principals) {
            if (manager == null) throw new ArgumentNullException(nameof(manager));
            return manager.Set(right, principals);
        }

        /// <summary>
        /// Grants the specified right to a principal using an existing manager instance (bulk-friendly).
        /// </summary>
        public static void Add(this UserRightsAssignment right, UserRights manager, string principal) {
            if (manager == null) throw new ArgumentNullException(nameof(manager));
            manager.Add(right, principal);
        }

        /// <summary>
        /// Grants the specified right to a sequence of principals using an existing manager instance.
        /// </summary>
        public static void Add(this UserRightsAssignment right, UserRights manager, IEnumerable<string> principals) {
            if (manager == null) throw new ArgumentNullException(nameof(manager));
            manager.Add(right, principals);
        }

        /// <summary>
        /// Removes the specified right from a principal using an existing manager instance.
        /// </summary>
        public static void Remove(this UserRightsAssignment right, UserRights manager, string principal) {
            if (manager == null) throw new ArgumentNullException(nameof(manager));
            manager.Remove(right, principal);
        }

        /// <summary>
        /// Removes the specified right from a sequence of principals using an existing manager instance.
        /// </summary>
        public static void Remove(this UserRightsAssignment right, UserRights manager, IEnumerable<string> principals) {
            if (manager == null) throw new ArgumentNullException(nameof(manager));
            manager.Remove(right, principals);
        }

        /// <summary>
        /// Asynchronously reconciles the right so that exactly the provided principals remain.
        /// </summary>
        public static async Task<UserRightSetResult> SetAsync(this UserRightsAssignment right, IEnumerable<string> principals, string systemName = null, CancellationToken cancellationToken = default) {
            using (var mgr = new UserRights(systemName)) {
                return await mgr.SetAsync(right, principals, cancellationToken).ConfigureAwait(false);
            }
        }
    }
}
