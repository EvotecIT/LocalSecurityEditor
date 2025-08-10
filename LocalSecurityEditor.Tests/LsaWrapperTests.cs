using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace LocalSecurityEditor.Tests;

public class LsaWrapperTests
{
    [Fact]
    public void InitLsaString_NullString_ThrowsArgumentNullException()
    {
        var method = typeof(LsaWrapper).GetMethod("InitLsaString", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        var ex = Assert.Throws<TargetInvocationException>(() => method!.Invoke(null, new object?[] { null }));
        Assert.IsType<ArgumentNullException>(ex.InnerException);
    }

    [Fact]
    public void InitLsaString_EmptyString_ThrowsArgumentNullException()
    {
        var method = typeof(LsaWrapper).GetMethod("InitLsaString", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        var ex = Assert.Throws<TargetInvocationException>(() => method!.Invoke(null, new object[] { string.Empty }));
        Assert.IsType<ArgumentNullException>(ex.InnerException);
    }

    [Fact]
    public void GetPrivileges_ReturnsDomainQualifiedNames()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return;
        }

        using var lsa = new LsaWrapper();
        var accounts = lsa.GetPrivileges(UserRightsAssignment.SeServiceLogonRight);
        Assert.All(accounts, account => Assert.Contains("\\", account));
    }
}
