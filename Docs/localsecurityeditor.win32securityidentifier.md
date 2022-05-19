# Win32SecurityIdentifier

Namespace: LocalSecurityEditor



```csharp
public class Win32SecurityIdentifier : System.IDisposable
```

Inheritance [Object](https://docs.microsoft.com/en-us/dotnet/api/system.object) → [Win32SecurityIdentifier](./localsecurityeditor.win32securityidentifier.md)<br>
Implements [IDisposable](https://docs.microsoft.com/en-us/dotnet/api/system.idisposable)

## Fields

### **securityIdentifier**



```csharp
public SecurityIdentifier securityIdentifier;
```

## Properties

### **Address**

Provides SecurityIdentifier Address

```csharp
public IntPtr Address { get; }
```

#### Property Value

[IntPtr](https://docs.microsoft.com/en-us/dotnet/api/system.intptr)<br>

## Constructors

### **Win32SecurityIdentifier(String)**



```csharp
public Win32SecurityIdentifier(string principal)
```

#### Parameters

`principal` [String](https://docs.microsoft.com/en-us/dotnet/api/system.string)<br>

### **Win32SecurityIdentifier(IdentityReference)**



```csharp
public Win32SecurityIdentifier(IdentityReference identityReference)
```

#### Parameters

`identityReference` IdentityReference<br>

### **Win32SecurityIdentifier(SecurityIdentifier)**



```csharp
public Win32SecurityIdentifier(SecurityIdentifier securityIdentifier)
```

#### Parameters

`securityIdentifier` SecurityIdentifier<br>

## Methods

### **Dispose()**

Disposes of an object

```csharp
public void Dispose()
```

### **Dispose(Boolean)**



```csharp
protected void Dispose(bool disposing)
```

#### Parameters

`disposing` [Boolean](https://docs.microsoft.com/en-us/dotnet/api/system.boolean)<br>
