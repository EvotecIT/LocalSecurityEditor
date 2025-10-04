# PrincipalInfo

Namespace: LocalSecurityEditor

Principal descriptor carrying both SID and name information.

## Properties

- `SidString` (`string`) — SID in SDDL format (e.g., `S-1-5-32-544`)
- `Domain` (`string`) — may be empty
- `Name` (`string`) — account name
- `AccountName` (`string`) — domain-qualified `Domain\Name` when available
- `Use` (`SidNameUse`) — classification (User, Group, etc.)

## Example

```csharp
var ura = UserRightsAssignment.SeServiceLogonRight.Get();
foreach (var p in ura.Principals)
{
    Console.WriteLine($"{p.AccountName} ({p.Use}) -> {p.SidString}");
}
```

