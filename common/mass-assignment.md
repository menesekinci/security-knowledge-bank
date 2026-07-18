# Mass Assignment / Auto Binding

**CWE:** CWE-915 (Mass Assignment), CWE-913 (Improper Control of Dynamically-Managed Code Resources)
**OWASP Top 10:2021:** A01 — Broken Access Control

---

## What Is Mass Assignment?

Mass assignment (also called auto-binding or autobinding) occurs when a framework **automatically binds HTTP request parameters to object properties** without filtering which properties are allowed. An attacker adds extra parameters to a request to modify fields they shouldn't have access to.

**Simple example:** You send `{"name": "Alice", "role": "user"}` to update a profile. The attacker sends `{"name": "Alice", "role": "admin"}` and becomes an admin.

## Why Vibe Coding Makes This Worse

- **AI loves ORMs and auto-mapping:** Frameworks like Rails, Laravel, Spring MVC, and Django REST Framework automatically map request data to objects
- **AI doesn't specify allowed fields:** Generated code uses `User.update(request.body)` without filtering
- **AI uses `**kwargs` / spread operators:** Python's `**data` or JavaScript's `...req.body` spread all fields
- **AI-generated GraphQL mutations:** Binds all fields from mutation arguments

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

## Common Mass Assignment Targets

| Field | Why Attackers Want It |
|---|---|
| `role`, `is_admin`, `is_staff` | Privilege escalation |
| `balance`, `credits`, `points` | Financial fraud |
| `is_verified`, `email_verified` | Bypass verification |
| `password`, `password_hash` | Account takeover |
| `api_key`, `secret` | API access |
| `is_active`, `is_banned` | Account manipulation |

---

## Prevention Checklist for AI Prompts

```
✅ MASS ASSIGNMENT PREVENTION:
- Never use __all__ or spread/merge entire request bodies into models
- Always use an allowlist of updatable fields
- Use Data Transfer Objects (DTOs) with only API-accessible fields
- Set read_only_fields on sensitive model properties
- Keep user-facing models separate from internal domain models
- Use libraries: Strong Parameters (Rails), @JsonIgnore (Spring), ModelSerializer.fields (DRF)
- Add middleware to strip unwanted parameters
- Test by sending extra fields in requests to verify they're ignored
```

---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Ruby on Rails — `attr_protected` bypass | CVE-2013-0276 | Crafted request modifies protected model attributes (mass assignment) — CVSS 4.3 (v2) |
| Ruby on Rails — Strong Parameters bypass via `create_with` | CVE-2014-3514 | Active Record `create_with` circumvents strong-parameter allowlists — CVSS 7.5 (v2) |
| Spring Framework — `class.classLoader` data binding | CVE-2010-1622 | Property binding reaches the class loader → arbitrary code execution — CVSS 6.0 (v2) |
| Spring Framework — "Spring4Shell" data binding | CVE-2022-22965 | Unsafe request-parameter binding reaches the class loader → RCE — CVSS 9.8 (v3.1) |
| Grails framework — data binding to class loader | CVE-2022-35912 | Data binding traverses to the class loader → RCE — CVSS 9.8 (v3.1) |

---

## References

- [OWASP Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [CWE-915: Mass Assignment](https://cwe.mitre.org/data/definitions/915.html)
- [Rails Guide — Strong Parameters](https://guides.rubyonrails.org/action_controller_overview.html#strong-parameters)
- [OWASP A01:2021 — Broken Access Control](https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/)
