---
source: "languages/ruby/rails-security.md"
title: "💎 Ruby on Rails Security — Complete Guide"
heading: "6. SQL Injection in Rails"
category: "language-vuln"
language: "ruby"
severity: "medium"
tags: [actionmailer, activestorage, csrf, escaping, injection, language-vuln, protection, route, ruby, security]
chunk: 7/10
---

## 6. SQL Injection in Rails

```ruby
# VULNERABLE: String interpolation in queries
User.where("email = '#{params[:email]}'")  # SQL injection!
User.where("name LIKE '%#{params[:q]}%'")  # SQL injection!
User.find_by_sql("SELECT * FROM users WHERE id = #{params[:id]}")  # SQL injection!

# SECURE: Use hash conditions
User.where(email: params[:email])
User.where("name LIKE ?", "%#{params[:q]}%")
User.find_by_sql(["SELECT * FROM users WHERE id = ?", params[:id]])

# SECURE: Use ActiveRecord scopes
class User < ApplicationRecord
  scope :by_email, ->(email) { where(email: email) }
  scope :search, ->(q) { where("name LIKE ?", "%#{sanitize_sql_like(q)}%") }
end
```

---