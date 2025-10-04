#### LocalSecurityEditor Release History

#### Unreleased
- Target frameworks: add `net9.0-windows`, keep `net8.0-windows`, `netstandard2.0`; restore `net472` for classic .NET. Dropped obsolete TFMs.
- Strict policy handling restored: `LsaOpenPolicy` uses `POLICY_ALL_ACCESS` and enumeration throws `UnauthorizedAccessException` on `ACCESS_DENIED` (empty only for `NO_MORE_ENTRIES`).
- Added async APIs: `GetStateAsync`, `EnumerateAsync`, `GetByRightAsync`, `GetByShortNameAsync`, `AddAsync`, `RemoveAsync`, `SetAsync` and async extension helpers.
- Performance: cache enum values for `Enumerate`/`GetByRight`/`GetByShortName` to avoid repeated allocations.
- Naming: `Win32SecurityIdentifier.securityIdentifier` → `SecurityIdentifier` (PascalCase).
- Thread-safety: mark dispose flags as `volatile` in `UserRights` and `Win32SecurityIdentifier`.
- Docs: extensive XML documentation for public APIs; README and Assets README updated (targets badge, OO API prominence, async usage, batching tip).
- Tests: add coverage for `PrincipalInfo.ToString()` and `Win32SecurityIdentifier` pinning (Windows-gated).

#### 0.4.0
- Add `Net 8.0` support
- Add `Net 7.0` support
- Add `Net 6.0` support
- Remove `Net 5.0` support
- Add ability to generate NT Service SIDs using `NTService.GenerateSID` method

#### 0.3.0 - 2022.10.16
- Fixes issue with unresolvable SIDs - should work fine for getting, removing and adding unresolvable SID now (tnx **jborean93**)
- Remove NET 4.5
- Added NET 4.5.2

#### 0.2.0 - 2022.05.19
  - Fixes account/principal transformation that would sometimes cause an error.

#### 0.1.0 - 2022.04.14
  - First release
