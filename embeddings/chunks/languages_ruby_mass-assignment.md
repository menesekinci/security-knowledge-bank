---
source: "languages/ruby/mass-assignment.md"
title: "🔴 Mass Assignment"
category: "language-vuln"
language: "ruby"
severity: "critical"
tags: [critical, does, example, language-vuln, rails, ruby, rule, what]
---

# 🔴 Mass Assignment

## What Is It?

The framework **automatically** assigns parameters coming from the user to an object's
fields. An attacker can escalate privileges by sending not just the form fields,
but also **fields that should not be sent** to the object.

## How Does It Appear in Vibe Coding?

```
Prompt: "Write a user registration API (name, email, password)"
AI: "Sure, let me assign params directly to the User model"
```

What AI writes:
```ruby
# 💀 Rails — Mass Assignment
class UsersController < ApplicationController
  def create
    # User can also send "role=admin"!
    @user = User.create(params[:user])  # 💀 All fields open!
    render json: @user
  end
end
```

## Example: Rails

```ruby
# User model:
#   name: string
#   email: string
#   password: string
#   role: string (admin/user)
#   admin: boolean

# 💀 VULNERABLE:
def create
  @user = User.create(params[:user])
  # POST: { user: { name: "hacker", role: "admin" } }
  # → @user.role = "admin" 💀
end

# ✅ SAFE (Strong Parameters):
def create
  @user = User.create(user_params)
end

private

def user_params
  params.require(:user).permit(:name, :email, :password)  # no role!
end
```

## Example: .NET/C#

```csharp
// 💀 VULNERABLE:
[HttpPost]
public IActionResult Create(UserDto user)
{
    // If UserDto has IsAdmin, the attacker can send it!
    var entity = new User
    {
        Name = user.Name,
        Email = user.Email,
        // IsAdmin was forgotten by AI!
    };
    // But tools like AutoMapper can map all fields
}
```

## Critical Rule for Vibe Coding
```
When transferring user data to an object:
- ONLY accept allowed fields (whitelist)
- NEVER do direct model.create/update from params
- Use DTO/ViewModel, don't use entity directly
- Avoid the "accept all fields" pattern
```

**Severity: 🔴 Critical** — Privilege escalation, admin bypass.
**CWE: CWE-915 (Mass Assignment)**
**OWASP: A01:2021 (Broken Access Control)**
