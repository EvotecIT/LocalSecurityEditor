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
        // Reflect internal count via public API
        var list = UserRights.Get();
        return list.Count;
    }
}
