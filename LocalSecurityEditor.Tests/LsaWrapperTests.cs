using System;
using System.Reflection;

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
}
