using System;
using Xunit;

namespace LocalSecurityEditor.Tests;

public class PrincipalInfoTests
{
    [Fact]
    public void ToString_WithDomainAndName_IncludesAccountAndSid()
    {
        var p = new PrincipalInfo("S-1-5-21-1-2-3-1001", "CONTOSO", "Alice", SidNameUse.User);
        var s = p.ToString();
        Assert.Contains("CONTOSO\\Alice", s);
        Assert.Contains("S-1-5-21-1-2-3-1001", s);
    }

    [Fact]
    public void ToString_WithoutName_FallsBackToSid()
    {
        var p = new PrincipalInfo("S-1-5-21-1-2-3-1001", null, null, SidNameUse.Unknown);
        var s = p.ToString();
        Assert.Equal("S-1-5-21-1-2-3-1001", s);
    }
}

