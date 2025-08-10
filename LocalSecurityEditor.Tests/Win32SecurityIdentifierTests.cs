using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace LocalSecurityEditor.Tests;

public class Win32SecurityIdentifierTests
{
    [Fact]
    public void Constructor_InvalidPrincipal_RethrowsIdentityNotMappedExceptionWithOriginalStackTrace()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return;
        }

        var ex = Assert.Throws<IdentityNotMappedException>(() => new Win32SecurityIdentifier("NonExistentUser"));
        Assert.Contains("Win32SecurityIdentifier.cs:line 18", ex.StackTrace);
    }
}
