using System;
using Xunit;

namespace LocalSecurityEditor.Tests;

public class NTServiceTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void GenerateSID_InvalidServiceName_ThrowsArgumentException(string? serviceName)
    {
        Assert.Throws<ArgumentException>(() => NTService.GenerateSID(serviceName!));
    }
}

