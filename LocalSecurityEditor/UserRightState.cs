using System;
using System.Collections.Generic;
#if NET5_0_OR_GREATER
using System.Runtime.Versioning;
#endif

namespace LocalSecurityEditor {
    /// <summary>
    /// Describes the metadata associated with a Windows user right (short name, display name and description).
    /// </summary>
#if NET5_0_OR_GREATER
    [SupportedOSPlatform("windows")]
#endif
    public sealed class UserRightDefinition {
        /// <summary>
        /// The user right identifier.
        /// </summary>
        public UserRightsAssignment Right { get; private set; }

        /// <summary>
        /// Short system name of the right (e.g. <c>SeDebugPrivilege</c>).
        /// </summary>
        public string ShortName { get; private set; }

        /// <summary>
        /// Friendly display name of the right.
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Human-readable description of what the right allows.
        /// </summary>
        public string Description { get; private set; }

        /// <summary>
        /// Creates a new definition for a user right.
        /// </summary>
        public UserRightDefinition(UserRightsAssignment right, string shortName, string name, string description) {
            Right = right;
            ShortName = shortName;
            Name = name;
            Description = description;
        }
    }

    /// <summary>
    /// Represents the current assignment state of a user right including the list of principals.
    /// </summary>
#if NET5_0_OR_GREATER
    [SupportedOSPlatform("windows")]
#endif
    public sealed class UserRightState {
        /// <summary>
        /// The user right this state describes.
        /// </summary>
        public UserRightsAssignment Right { get; private set; }

        /// <summary>
        /// Short system name of the right.
        /// </summary>
        public string ShortName { get; private set; }

        /// <summary>
        /// Friendly display name of the right.
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Human-readable description of the right.
        /// </summary>
        public string Description { get; private set; }

        /// <summary>
        /// Principals currently assigned the right.
        /// </summary>
        public IReadOnlyList<PrincipalInfo> Principals { get; private set; }

        /// <summary>
        /// Number of principals assigned the right.
        /// </summary>
        public int Count { get { return Principals == null ? 0 : Principals.Count; } }

        /// <summary>
        /// Creates a <see cref="UserRightState"/> from the given definition and principal list.
        /// </summary>
        public UserRightState(UserRightDefinition def, IReadOnlyList<PrincipalInfo> principals) {
            Right = def.Right;
            ShortName = def.ShortName;
            Name = def.Name;
            Description = def.Description;
            Principals = principals;
        }

        /// <summary>
        /// Returns a concise summary string for diagnostics.
        /// </summary>
        public override string ToString() { return Name + " (" + ShortName + ") : " + Count + " principals"; }
    }
}
