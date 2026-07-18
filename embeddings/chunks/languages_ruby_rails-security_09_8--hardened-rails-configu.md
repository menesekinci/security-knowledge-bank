---
source: "languages/ruby/rails-security.md"
title: "💎 Ruby on Rails Security — Complete Guide"
heading: "8. Hardened Rails Configuration"
category: "language-vuln"
language: "ruby"
severity: "medium"
tags: [actionmailer, activestorage, csrf, escaping, injection, language-vuln, protection, route, ruby, security]
chunk: 9/10
---

## 8. Hardened Rails Configuration

```ruby
# config/application.rb — Security hardening
module MyApp
  class Application < Rails::Application
    # Force SSL in production
    config.force_ssl = true
    
    # Secure cookies
    config.session_store :cookie_store, 
      key: '_myapp_session',
      secure: Rails.env.production?,
      httponly: true,
      same_site: :lax
    
    # Content Security Policy
    config.content_security_policy do |policy|
      policy.default_src :self, :https
      policy.font_src    :self, :https, :data
      policy.img_src     :self, :https, :data
      policy.object_src  :none
      policy.script_src  :self, :https
      policy.style_src   :self, :https
      policy.frame_ancestors :none
    end
    
    # HSTS
    config.hsts = {
      expires: 1.year,
      preload: true,
      subdomains: true
    }
    
    # Rate limiting (Rails 7.1+)
    config.middleware.use Rack::Attack
  end
end
```

---