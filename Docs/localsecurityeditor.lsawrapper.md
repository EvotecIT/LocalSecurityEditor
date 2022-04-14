# LsaWrapper

Namespace: LocalSecurityEditor



```csharp
public sealed class LsaWrapper : System.IDisposable
```

Inheritance [Object](https://docs.microsoft.com/en-us/dotnet/api/system.object) → [LsaWrapper](./localsecurityeditor.lsawrapper.md)<br>
Implements [IDisposable](https://docs.microsoft.com/en-us/dotnet/api/system.idisposable)

## Constructors

### **LsaWrapper()**



```csharp
public LsaWrapper()
```

### **LsaWrapper(String)**



```csharp
public LsaWrapper(string systemName)
```

#### Parameters

`systemName` [String](https://docs.microsoft.com/en-us/dotnet/api/system.string)<br>

## Methods

### **GetPrivileges(UserRightsAssignment)**



```csharp
public String[] GetPrivileges(UserRightsAssignment privilege)
```

#### Parameters

`privilege` [UserRightsAssignment](./localsecurityeditor.userrightsassignment.md)<br>

#### Returns

[String[]](https://docs.microsoft.com/en-us/dotnet/api/system.string)<br>

### **AddPrivileges(String, UserRightsAssignment)**



```csharp
public void AddPrivileges(string account, UserRightsAssignment privilege)
```

#### Parameters

`account` [String](https://docs.microsoft.com/en-us/dotnet/api/system.string)<br>

`privilege` [UserRightsAssignment](./localsecurityeditor.userrightsassignment.md)<br>

### **RemovePrivileges(String, UserRightsAssignment)**



```csharp
public void RemovePrivileges(string account, UserRightsAssignment privilege)
```

#### Parameters

`account` [String](https://docs.microsoft.com/en-us/dotnet/api/system.string)<br>

`privilege` [UserRightsAssignment](./localsecurityeditor.userrightsassignment.md)<br>

### **Dispose()**

Dispose LsaWrapper

```csharp
public void Dispose()
```

### **Finalize()**



```csharp
protected void Finalize()
```
