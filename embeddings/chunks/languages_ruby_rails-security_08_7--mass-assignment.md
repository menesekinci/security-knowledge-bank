---
source: "languages/ruby/rails-security.md"
title: "💎 Ruby on Rails Security — Complete Guide"
heading: "7. Mass Assignment"
category: "language-vuln"
language: "ruby"
severity: "medium"
tags: [actionmailer, activestorage, csrf, escaping, injection, language-vuln, protection, route, ruby, security]
chunk: 8/10
---

## 7. Mass Assignment

```ruby
# VULNERABLE: Mass assignment via permit!
class UsersController < ApplicationController
  def update
    @user = User.find(params[:id])
    @user.update!(params.permit!)  # User can set role=admin!
  end
end

# VULNERABLE: Overly permissive params
def user_params
  params.require(:user).permit(:name, :email, :password, :role, :admin)
end

# SECURE: Strict params allowlist
def user_params
  params.require(:user).permit(:name, :email, :password)
end

# BEST: Dual approach — permit + policy
class UserPolicy
  def permitted_attributes
    if user.admin?
      [:name, :email, :password, :role]
    else
      [:name, :email, :password]
    end
  end
end
```

---