using System;

namespace LocalSecurityEditor {
    /// <summary>
    /// Optional diagnostics callbacks. Assign handlers in your application to capture
    /// internal library events without adding logging dependencies.
    /// </summary>
    public static class Diagnostics {
        /// <summary>
        /// Invoked when a non-fatal error occurs inside the library (e.g., exceptions during dispose).
        /// First argument is a short message describing the context; second is the exception instance.
        /// If <c>null</c>, the library does not emit diagnostics.
        /// </summary>
        public static Action<string, Exception> OnError;

        /// <summary>
        /// Invoked to emit informational messages (rarely used). If <c>null</c>, no info messages are produced.
        /// </summary>
        public static Action<string> OnInfo;
    }
}
