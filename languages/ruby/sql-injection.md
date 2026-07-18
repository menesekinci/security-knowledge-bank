# 💎 Ruby SQL Injection (ActiveRecord)

## How Does It Come Up in Vibe Coding?
```
Prompt: "Write an API that searches users"
AI: User.where("name LIKE '%#{params[:q]}%'")  # 💀
```

## Example
```ruby
# 💀 VULNERABLE:
def search
  @users = User.where("name LIKE '%#{params[:query]}%'")
  # params[:query] = "'; DROP TABLE users; --"
end

# ✅ SECURE:
def search
  @users = User.where("name LIKE ?", "%#{params[:query]}%")
  # ActiveRecord placeholders → protected against SQL injection
end

# ✅ Array syntax is safe too:
User.where("name LIKE :q OR email LIKE :q", q: "%#{params[:query]}%")
```

## Rule
- In ActiveRecord, `where("?", param)` is safe
- A hash condition `where(name: params[:name])` is safe
- `where("string #{interpolation}")` is **DANGEROUS**
- If you use `find_by_sql`, sanitize manually

---

**Severity: 🔴 Critical**
