using System.Security.Principal;
using Xunit;

namespace LocalSecurityEditor.Tests;

public class Win32SecurityIdentifierTests2
{
    [Fact]
    public void FromSecurityIdentifier_ExposesPinnedAddress()
    {
        var sid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        using var pinned = new Win32SecurityIdentifier(sid);
        Assert.NotEqual(System.IntPtr.Zero, pinned.Address);
        Assert.Equal(sid.Value, pinned.SecurityIdentifier.Value);
    }
}
