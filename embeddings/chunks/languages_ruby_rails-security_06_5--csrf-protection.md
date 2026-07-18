---
source: "languages/ruby/rails-security.md"
title: "💎 Ruby on Rails Security — Complete Guide"
heading: "5. CSRF Protection"
category: "language-vuln"
language: "ruby"
severity: "medium"
tags: [actionmailer, activestorage, csrf, escaping, injection, language-vuln, protection, route, ruby, security]
chunk: 6/10
---

## 5. CSRF Protection

```ruby
# VULNERABLE: Disabling CSRF globally
class ApplicationController < ActionController::Base
  protect_from_forgery with: :null_session  # No CSRF check!
end

# VULNERABLE: Disabling CSRF for "API" endpoints
class ApiController < ApplicationController
  protect_from_forgery except: [:create]  # Dangerous partial disable
end

# SECURE: API with token-based auth (no session)
class ApiController < ApplicationController
  protect_from_forgery with: :null_session  # OK if using API token
  
  before_action :authenticate_api_token
  
  private
  
  def authenticate_api_token
    @current_user = User.find_by(api_token: request.headers['X-API-Token'])
    head :unauthorized unless @current_user
  end
end
```

---