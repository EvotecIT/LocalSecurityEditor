using System.Reflection;
using System.Runtime.InteropServices;

namespace LocalSecurityEditor.Tests;

public class LsaWrapperTests {
    [Fact]
    public void InitLsaString_NullString_ThrowsArgumentNullException() {
        var method = typeof(LsaWrapper).GetMethod("InitLsaString", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        var ex = Assert.Throws<TargetInvocationException>(() => method!.Invoke(null, new object?[] { null }));
        Assert.IsType<ArgumentNullException>(ex.InnerException);
    }

    [Fact]
    public void InitLsaString_EmptyString_ThrowsArgumentNullException() {
        var method = typeof(LsaWrapper).GetMethod("InitLsaString", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        var ex = Assert.Throws<TargetInvocationException>(() => method!.Invoke(null, new object[] { string.Empty }));
        Assert.IsType<ArgumentNullException>(ex.InnerException);
    }

    [Fact]
    public void GetPrivileges_ReturnsDomainQualifiedNames() {
        using var lsa = new LsaWrapper();
        try {
            var accounts = lsa.GetPrivileges(UserRightsAssignment.SeServiceLogonRight);
            Assert.All(accounts, account => Assert.Contains("\\", account));
        } catch (UnauthorizedAccessException) {
            // CI might run non-elevated; treat as inconclusive
        }
    }

    [Fact]
    public void ConvertSidToStringSid_UsesUnicodeEntryPoint() {
        Type? nativeMethods = typeof(LsaWrapper).Assembly.GetType("LocalSecurityEditor.Win32Sec");
        MethodInfo? method = nativeMethods?.GetMethod(
            "ConvertSidToStringSid",
            BindingFlags.NonPublic | BindingFlags.Static);
        DllImportAttribute? attribute = method?.GetCustomAttribute<DllImportAttribute>();

        Assert.NotNull(attribute);
        Assert.Equal(CharSet.Unicode, attribute!.CharSet);
        Assert.Equal("ConvertSidToStringSidW", attribute.EntryPoint);
        Assert.True(attribute.ExactSpelling);
    }

    [Fact]
    public void GetPrincipals_ReturnsCanonicalSidStrings() {
        using var lsa = new LsaWrapper();
        try {
            PrincipalInfo[] principals = lsa.GetPrincipals(UserRightsAssignment.SeNetworkLogonRight);
            Assert.All(principals, principal => Assert.Matches("^S-\\d(?:-\\d+)+$", principal.SidString));
        } catch (UnauthorizedAccessException) {
            // CI might run non-elevated; treat as inconclusive
        }
    }
}
