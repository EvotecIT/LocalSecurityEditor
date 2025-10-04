using System.Runtime.InteropServices;

namespace LocalSecurityEditor.Tests;

public class UserRightsSetTests {
    [Fact]
    public void Set_WithInvalidPrincipal_HandlesGracefully() {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
        var right = UserRightsAssignment.SeBatchLogonRight;
        try {
            using var ur = new UserRights();
            var result = ur.Set(right, new[] { "ThisPrincipalDoesNotExist$" }, new List<PrincipalInfo>());
            Assert.NotNull(result);
            Assert.Contains(result.Unresolved, u => u.StartsWith("ThisPrincipalDoesNotExist$", StringComparison.Ordinal));
        } catch (UnauthorizedAccessException) {
            // Running non-elevated; treat as skipped
        }
    }
}

