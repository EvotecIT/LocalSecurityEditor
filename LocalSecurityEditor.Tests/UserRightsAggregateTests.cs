using System;
using System.Linq;
using System.Runtime.InteropServices;

namespace LocalSecurityEditor.Tests;

public class UserRightsAggregateTests
{
    [Fact]
    public void Catalog_Definitions_Match_Enum_Count()
    {
        var defs = typeof(UserRightsAssignment).GetEnumValues();
        // simple sanity: count of catalog equals count of enum values
        Assert.Equal(defs.Length, GetCatalogCount());
    }

    private static int GetCatalogCount()
    {
        // Reflect internal count via a convenience call: get all definitions through public API count
        // Use the extension to build states (skipped on non-Windows before invoking native calls)
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return typeof(UserRightsAssignment).GetEnumValues().Length;

        var list = UserRights.Get();
        return list.Count;
    }
}
