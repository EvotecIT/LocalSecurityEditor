using System;
using System.Linq;
using System.Runtime.InteropServices;

namespace LocalSecurityEditor.Tests;

public class UserRightsApiTests
{
    [Fact]
    public void Extensions_CompileAndNoopOnNonWindows()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // The call will attempt to P/Invoke on non-Windows if executed; just ensure method binding is available.
            return;
        }

        // Exercise Get using the new OO API. We don't assert contents here.
        var one = UserRightsAssignment.SeServiceLogonRight.Get();
        Assert.NotNull(one);
    }
}
