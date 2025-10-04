using System;
using System.Linq;
using System.Runtime.InteropServices;

namespace LocalSecurityEditor.Tests;

public class UserRightsApiTests
{
    [Fact]
    public void Extensions_BasicGet_DoesNotThrow()
    {
        var one = UserRightsAssignment.SeServiceLogonRight.Get();
        Assert.NotNull(one);
    }
}
