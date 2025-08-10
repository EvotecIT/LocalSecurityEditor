using System.Runtime.InteropServices;
using Xunit;

namespace LocalSecurityEditor.Tests;

    public class ServiceSidTests
    {
    [Theory]
    [InlineData("ADSync", "S-1-5-80-3245704983-3664226991-764670653-2504430226-901976451")]
    [InlineData("MSSQLSERVER", "S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003")]
    [InlineData("W32Time", "S-1-5-80-4267341169-2882910712-659946508-2704364837-2204554466")]
    [InlineData("TrustedInstaller", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")]
    public void GenerateSID_KnownServiceName_ReturnsExpectedSid(string serviceName, string expectedSid)
    {
        string sid = NTService.GenerateSID(serviceName);
        Assert.Equal(expectedSid, sid);
    }

    [Theory]
    [InlineData("S-1-5-80-4267341169-2882910712-659946508-2704364837-2204554466", "W32Time")]
    [InlineData("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", "TrustedInstaller")]
    public void ResolveServiceName_KnownSid_ReturnsExpectedServiceName(string sid, string expectedServiceName)
    {
        string? serviceName = NTService.ResolveServiceName(sid);

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Assert.Null(serviceName);
            return;
        }

        Assert.Equal(expectedServiceName, serviceName);
    }
}
