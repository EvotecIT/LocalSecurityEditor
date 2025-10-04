using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace LocalSecurityEditor.Tests;

public class Win32SecurityIdentifierTests
{
    [Fact]
    public void Constructor_InvalidPrincipal_RethrowsArgumentExceptionWithOriginalStackTrace()
    {
        var ex = Assert.Throws<ArgumentException>(() => new Win32SecurityIdentifier("NonExistentUser"));
        Assert.Contains("Win32SecurityIdentifier..ctor", ex.StackTrace);
    }
}
