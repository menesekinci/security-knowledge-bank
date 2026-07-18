---
source: "common/mass-assignment.md"
title: "Mass Assignment / Auto Binding"
heading: "Fixed Code Examples"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common, common-vuln, fixed, mass, vibe, vulnerable, what]
chunk: 5/9
---

## Fixed Code Examples

### Rails — Fixed

```ruby
# ✅ SECURE: use strong parameters
def update
  @user = User.find(params[:id])
  @user.update(user_params)  # Only permitted fields
  redirect_to @user
end

private

def user_params
  params.require(:user).permit(:name, :email, :avatar)
  # :role, :is_admin, :balance are NOT permitted
end
```

### Node.js (Mongoose) — Fixed

```javascript
// ✅ SECURE: explicitly pick allowed fields
const ALLOWED_UPDATES = ['name', 'email', 'avatar'];

app.put('/user/:id', async (req, res) => {
    const user = await User.findById(req.params.id);

    // Only update allowed fields
    for (const field of ALLOWED_UPDATES) {
        if (req.body[field] !== undefined) {
            user[field] = req.body[field];
        }
    }
    // Or use a library:
    // const pick = require('lodash.pick');
    // Object.assign(user, pick(req.body, ALLOWED_UPDATES));

    await user.save();
    res.json(user);
});
```

### Python (Django REST) — Fixed

```python
# ✅ SECURE: explicit fields list
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'avatar']  # Explicit allowlist
        read_only_fields = ['id']  # Never changeable
        # is_staff, is_superuser are NOT in fields

# OR use extra_kwargs for extra protection
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'avatar', 'is_active']
        read_only_fields = ['id', 'is_active']
```

### Java (Spring) — Fixed

```java
// ✅ SECURE: use DTOs with only allowed fields
public class UserUpdateDto {
    private String name;
    private String email;
    // No role field here!

    // getters/setters...
}

@PutMapping("/user/{id}")
public User updateUser(@PathVariable Long id, @Valid @RequestBody UserUpdateDto dto) {
    User user = userRepository.findById(id).orElseThrow();
    // Only copy allowed fields
    if (dto.getName() != null) user.setName(dto.getName());
    if (dto.getEmail() != null) user.setEmail(dto.getEmail());
    return userRepository.save(user);
}
```

### C# (ASP.NET) — Fixed

```csharp
[HttpPut("user/{id}")]
public IActionResult UpdateUser(int id, [FromBody] UserUpdateDto dto)
{
    var user = _context.Users.Find(id);
    // Only map allowed fields explicitly
    user.Name = dto.Name;
    user.Email = dto.Email;
    // NOT: user.IsAdmin, user.Balance
    _context.SaveChanges();
}
```

---