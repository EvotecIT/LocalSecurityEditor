using System;
using LocalSecurityEditor;
using Xunit;

namespace LocalSecurityEditor.Tests;

public class Win32SecurityIdentifierTests
{
#if NETFRAMEWORK
    [Fact(Skip = "Pinned object count not available on .NET Framework")]
    public void Finalizer_FreesPinnedHandle_NoDispose()
    {
    }
#else
    [Fact]
    public void Finalizer_FreesPinnedHandle_NoDispose()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        long pinnedBefore = GC.GetGCMemoryInfo().PinnedObjectsCount;

        var sid = new Win32SecurityIdentifier("S-1-5-18");
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        long pinnedDuring = GC.GetGCMemoryInfo().PinnedObjectsCount;
        GC.KeepAlive(sid);
        Assert.True(pinnedDuring > pinnedBefore);

        sid = null;
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        long pinnedAfter = GC.GetGCMemoryInfo().PinnedObjectsCount;
        Assert.Equal(pinnedBefore, pinnedAfter);
    }
#endif
}
