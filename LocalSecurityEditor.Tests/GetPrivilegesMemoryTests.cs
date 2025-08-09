using System;
using System.Runtime.InteropServices;
using LocalSecurityEditor;
using Xunit;

namespace LocalSecurityEditor.Tests {
    public class GetPrivilegesMemoryTests {
        [Fact]
        public void GetPrivileges_ReleaseNativeMemory() {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
                return;
            }

            const int iterations = 5;
            using var wrapper = new LsaWrapper();
            long before = GC.GetTotalMemory(true);

            for (int i = 0; i < iterations; i++) {
                wrapper.GetPrivileges(UserRightsAssignment.SeShutdownPrivilege);
            }

            long after = GC.GetTotalMemory(true);
            Assert.True(after - before < 1024 * 1024);
        }
    }
}
