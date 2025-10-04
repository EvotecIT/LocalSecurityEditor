# UserRights

Namespace: LocalSecurityEditor

High-level facade for listing and managing User Rights Assignments (URAs).

## Static Methods

`UserRights.Get()`

- Returns: `IReadOnlyList<UserRightState>` — one object per user right with principals.

`UserRights.Get(string systemName)`

- Returns: `IReadOnlyList<UserRightState>` for a remote machine.

## Instance Methods

`Enumerate()` → `IReadOnlyList<UserRightState>`

`GetState(UserRightsAssignment right)` → `UserRightState`

`GetByRight()` → `Dictionary<UserRightsAssignment, UserRightState>`

`GetByShortName(StringComparer comparer = null)` → `Dictionary<string, UserRightState>`

`Add(UserRightsAssignment right, IEnumerable<string> principals)`

`Remove(UserRightsAssignment right, IEnumerable<string> principals)`

`Set(UserRightsAssignment right, IEnumerable<string> principals)` → `UserRightSetResult`

## Examples

```csharp
// All URAs (local)
var all = UserRights.Get();

// Single URA
var svc = new UserRights().GetState(UserRightsAssignment.SeServiceLogonRight);

// Remote
var allRemote = UserRights.Get("SERVER01");
```

