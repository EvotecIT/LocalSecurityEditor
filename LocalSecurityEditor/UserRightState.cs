using System;
using System.Collections.Generic;
#if NET5_0_OR_GREATER
using System.Runtime.Versioning;
#endif

namespace LocalSecurityEditor {
#if NET5_0_OR_GREATER
    [SupportedOSPlatform("windows")]
#endif
    public sealed class UserRightDefinition {
        public UserRightsAssignment Right { get; private set; }
        public string ShortName { get; private set; }
        public string Name { get; private set; }
        public string Description { get; private set; }

        public UserRightDefinition(UserRightsAssignment right, string shortName, string name, string description) {
            Right = right;
            ShortName = shortName;
            Name = name;
            Description = description;
        }
    }

#if NET5_0_OR_GREATER
    [SupportedOSPlatform("windows")]
#endif
    public sealed class UserRightState {
        public UserRightsAssignment Right { get; private set; }
        public string ShortName { get; private set; }
        public string Name { get; private set; }
        public string Description { get; private set; }
        public IReadOnlyList<PrincipalInfo> Principals { get; private set; }

        public int Count { get { return Principals == null ? 0 : Principals.Count; } }

        public UserRightState(UserRightDefinition def, IReadOnlyList<PrincipalInfo> principals) {
            Right = def.Right;
            ShortName = def.ShortName;
            Name = def.Name;
            Description = def.Description;
            Principals = principals;
        }

        public override string ToString() { return Name + " (" + ShortName + ") : " + Count + " principals"; }
    }
}

