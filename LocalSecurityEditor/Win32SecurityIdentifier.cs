using System;
using System.Linq.Expressions;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace LocalSecurityEditor {
    public class Win32SecurityIdentifier : IDisposable {
        private bool disposed = false;
        private GCHandle handle;
        private Byte[] buffer;

        public SecurityIdentifier securityIdentifier { get; }

        public Win32SecurityIdentifier(String principal) {
            NTAccount account = new NTAccount(principal);
            SecurityIdentifier sid;
            try {
                sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
            } catch (IdentityNotMappedException e) {
                try {
                    sid = new SecurityIdentifier(principal);
                } catch (ArgumentException) {
                    throw;
                }
            }

            this.securityIdentifier = sid;

            buffer = new Byte[securityIdentifier.BinaryLength];
            securityIdentifier.GetBinaryForm(buffer, 0);

            handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        }

        public Win32SecurityIdentifier(IdentityReference identityReference) : this((SecurityIdentifier)identityReference.Translate(typeof(SecurityIdentifier))) { }

        public Win32SecurityIdentifier(SecurityIdentifier securityIdentifier) {
            this.securityIdentifier = securityIdentifier;

            buffer = new Byte[securityIdentifier.BinaryLength];
            securityIdentifier.GetBinaryForm(buffer, 0);

            handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        }

        /// <summary>
        /// Provides SecurityIdentifier Address
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
        /// Disposes of an object
        /// </summary>
        public void Dispose() {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing) {
            if (disposed) return;

            if (disposing && handle.IsAllocated)
                handle.Free();

            disposed = true;
        }
    }

}
