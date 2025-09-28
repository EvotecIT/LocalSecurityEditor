# UserRightState

Namespace: LocalSecurityEditor

Represents a configured User Right with its principals.

## Properties

- `Right` (`UserRightsAssignment`)
- `ShortName` (`string`) — e.g., `SeServiceLogonRight`
- `Name` (`string`) — friendly name
- `Description` (`string`)
- `Principals` (`IReadOnlyList<PrincipalInfo>`)
- `Count` (`int`) — number of principals

## Example

```csharp
var svc = UserRightsAssignment.SeServiceLogonRight.Get();
Console.WriteLine($"{svc.Name} -> {svc.Count}");
foreach (var p in svc.Principals)
{
    Console.WriteLine($"{p.AccountName} ({p.SidString})");
}
```

