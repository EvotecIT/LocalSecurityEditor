using System;
using System.Reflection;
using System.Runtime.InteropServices;
using LocalSecurityEditor;
using Xunit;

namespace LocalSecurityEditor.Tests;

public class Win32SecurityIdentifierTests
{
    [Fact]
    public void Finalizer_FreesPinnedHandle_NoDispose()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return;
        }

        var sid = new Win32SecurityIdentifier("S-1-5-18");

        var bufferField = typeof(Win32SecurityIdentifier).GetField("buffer", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var buffer = (byte[])bufferField.GetValue(sid)!;

        var sidWeak = new WeakReference(sid);
        var bufferWeak = new WeakReference(buffer);

        sid = null;
        buffer = null;

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        Assert.False(bufferWeak.IsAlive);
        Assert.False(sidWeak.IsAlive);
    }
}
