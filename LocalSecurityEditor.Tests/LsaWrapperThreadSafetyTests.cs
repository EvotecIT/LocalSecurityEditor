using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace LocalSecurityEditor.Tests;

public class LsaWrapperThreadSafetyTests
{
    [Fact]
    public void Disposed_Then_GetPrivileges_Throws_ObjectDisposed()
    {
        var lsa = new LsaWrapper();
        lsa.Dispose();
        Assert.Throws<ObjectDisposedException>(() => lsa.GetPrivileges(UserRightsAssignment.SeBatchLogonRight));
    }

    [Fact]
    public void Disposed_Then_AddPrivileges_Throws_ObjectDisposed()
    {
        var lsa = new LsaWrapper();
        lsa.Dispose();
        Assert.Throws<ObjectDisposedException>(() => lsa.AddPrivileges("S-1-5-32-544", UserRightsAssignment.SeBatchLogonRight));
    }

    [Fact]
    public async Task Parallel_Reads_On_Disposed_Wrapper_Fail_Deterministically()
    {
        var lsa = new LsaWrapper();
        lsa.Dispose();
        var rights = new []
        {
            UserRightsAssignment.SeServiceLogonRight,
            UserRightsAssignment.SeBatchLogonRight,
            UserRightsAssignment.SeDebugPrivilege
        };
        var tasks = rights.Select(r => Task.Run(() => Assert.Throws<ObjectDisposedException>(() => lsa.GetPrivileges(r))));
        await Task.WhenAll(tasks);
    }
}
