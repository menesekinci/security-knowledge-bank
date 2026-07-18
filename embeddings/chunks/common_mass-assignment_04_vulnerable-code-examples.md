---
source: "common/mass-assignment.md"
title: "Mass Assignment / Auto Binding"
heading: "Vulnerable Code Examples"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common, common-vuln, fixed, mass, vibe, vulnerable, what]
chunk: 4/9
---

## Vulnerable Code Examples

### Rails — Vulnerable

```ruby
# 🔴 VULNERABLE: mass assignment without strong parameters
def update
  @user = User.find(params[:id])
  @user.update(params[:user])  # Attacker adds :role, :admin, :is_verified
  redirect_to @user
end
# Attacker POSTs: user[name]=Alice&user[role]=admin
```

### Node.js (Mongoose) — Vulnerable

```javascript
// 🔴 VULNERABLE: spreads all request body fields
app.put('/user/:id', async (req, res) => {
    const user = await User.findById(req.params.id);
    Object.assign(user, req.body);  // Attacker adds { isAdmin: true, balance: 999999 }
    await user.save();
    res.json(user);
});
```

### Python (Django REST) — Vulnerable

```python
# 🔴 VULNERABLE: ModelSerializer without read_only_fields
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'  # Exposes ALL fields including is_staff!

@api_view(['PUT'])
def update_user(request, pk):
    user = User.objects.get(pk=pk)
    serializer = UserSerializer(user, data=request.data)
    if serializer.is_valid():
        serializer.save()  # Saves is_staff=True if attacker sends it
```

### Java (Spring) — Vulnerable

```java
@PutMapping("/user/{id}")
public User updateUser(@PathVariable Long id, @RequestBody User user) {
    // 🔴 VULNERABLE: Spring auto-binds all JSON fields
    // POSTing {"role": "ADMIN"} changes the user's role
    return userRepository.save(user);
}
```

### C# (ASP.NET) — Vulnerable

```csharp
[HttpPut("user/{id}")]
// 🔴 VULNERABLE: binds all properties
public IActionResult UpdateUser(int id, UserDto user) {
    var existing = _context.Users.Find(id);
    _context.Entry(existing).CurrentValues.SetValues(user);
    // Attacker sends: { "isAdmin": true, "balance": 1000000 }
    _context.SaveChanges();
}
```