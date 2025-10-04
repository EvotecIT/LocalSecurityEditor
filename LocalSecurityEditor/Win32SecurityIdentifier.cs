using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace LocalSecurityEditor {
    /// <summary>
    /// Helper wrapper around <see cref="SecurityIdentifier"/> that pins the underlying
    /// binary form in memory and exposes a stable unmanaged address for P/Invoke calls.
    /// </summary>
    public class Win32SecurityIdentifier : IDisposable {
        private volatile bool disposed = false;
        private GCHandle handle;
        private Byte[] buffer;

        /// <summary>
        /// The strongly typed SID represented by this instance.
        /// </summary>
        public SecurityIdentifier SecurityIdentifier { get; }

        /// <summary>
        /// Creates an instance from an account name or SID string.
        /// </summary>
        /// <param name="principal">Account name (e.g. <c>DOMAIN\\User</c>) or SID string.</param>
        /// <exception cref="IdentityNotMappedException">Thrown when the account cannot be resolved to a SID.</exception>
        /// <exception cref="ArgumentException">Thrown when the supplied SID string is invalid.</exception>
        public Win32SecurityIdentifier(String principal) {
            NTAccount account = new NTAccount(principal);
            SecurityIdentifier sid;
            try {
                sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
            } catch (IdentityNotMappedException) {
                try {
                    sid = new SecurityIdentifier(principal);
                } catch (ArgumentException) {
                    throw;
                }
            }

            this.SecurityIdentifier = sid;

            buffer = new Byte[SecurityIdentifier.BinaryLength];
            SecurityIdentifier.GetBinaryForm(buffer, 0);

            handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        }

        /// <summary>
        /// Creates an instance from an <see cref="IdentityReference"/> by translating to a <see cref="SecurityIdentifier"/>.
        /// </summary>
        public Win32SecurityIdentifier(IdentityReference identityReference) : this((SecurityIdentifier)identityReference.Translate(typeof(SecurityIdentifier))) { }

        /// <summary>
        /// Creates an instance from an existing <see cref="SecurityIdentifier"/>.
        /// </summary>
        public Win32SecurityIdentifier(SecurityIdentifier securityIdentifier) {
            this.SecurityIdentifier = securityIdentifier;

            buffer = new Byte[securityIdentifier.BinaryLength];
            securityIdentifier.GetBinaryForm(buffer, 0);

            handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        }

        /// <summary>
        /// Provides a pointer to the pinned binary SID suitable for native APIs.
        /// </summary>
        public IntPtr Address {
            get {
                if (handle.IsAllocated) {
                    return handle.AddrOfPinnedObject();
                } else {
                    return IntPtr.Zero;
                }
            }
        }

        /// <summary>
        /// Releases the pinned buffer and suppresses finalization.
        /// </summary>
        public void Dispose() {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Implements the dispose pattern.
        /// </summary>
        protected virtual void Dispose(bool disposing) {
            if (disposed) return;

            if (disposing && handle.IsAllocated)
                handle.Free();

            disposed = true;
        }
    }

}
