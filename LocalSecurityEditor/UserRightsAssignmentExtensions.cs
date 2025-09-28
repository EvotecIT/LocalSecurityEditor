using System;
using System.Collections.Generic;
using System.Linq;

namespace LocalSecurityEditor {
    public static class UserRightsAssignmentExtensions {
        // Single-right getter returning a typed state
        public static UserRightState Get(this UserRightsAssignment right, string systemName = null) {
            using (var mgr = new UserRights(systemName)) {
                return mgr.GetState(right);
            }
        }

        public static void Add(this UserRightsAssignment right, string principal, string systemName = null) {
            using (var mgr = new UserRights(systemName)) {
                mgr.Add(right, principal);
            }
        }

        public static void Add(this UserRightsAssignment right, IEnumerable<string> principals, string systemName = null) {
            using (var mgr = new UserRights(systemName)) {
                mgr.Add(right, principals);
            }
        }

        public static void Remove(this UserRightsAssignment right, string principal, string systemName = null) {
            using (var mgr = new UserRights(systemName)) {
                mgr.Remove(right, principal);
            }
        }

        public static void Remove(this UserRightsAssignment right, IEnumerable<string> principals, string systemName = null) {
            using (var mgr = new UserRights(systemName)) {
                mgr.Remove(right, principals);
            }
        }

        public static UserRightSetResult Set(this UserRightsAssignment right, IEnumerable<string> principals, string systemName = null) {
            using (var mgr = new UserRights(systemName)) {
                return mgr.Set(right, principals);
            }
        }
    }
}
