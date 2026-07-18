---
source: "languages/ruby/rails-security.md"
title: "💎 Ruby on Rails Security — Complete Guide"
heading: "1. Route Security"
category: "language-vuln"
language: "ruby"
severity: "medium"
tags: [actionmailer, activestorage, csrf, escaping, injection, language-vuln, protection, route, ruby, security]
chunk: 2/10
---

## 1. Route Security

### RESTful Route Best Practices

```ruby
# VULNERABLE: Overly broad routes expose internal actions
resources :users do
  collection do
    get :admin_dashboard       # No auth check on route level
    post :impersonate          # Privilege escalation risk
  end
  member do
    put :update_role           # Mass assignment risk
  end
end

# SECURE: Explicit route restrictions + namespace for admin
namespace :admin do
  constraints ->(req) { req.session[:user_id] && User.find(req.session[:user_id]).admin? } do
    resources :dashboards, only: [:index]
  end
end

resources :users, only: [:show, :edit, :update] do
  # No admin operations in user scope
end
```

### Route Wildcard Dangers

```ruby
# VULNERABLE (CVE-2024-XXXX pattern): Wildcard route exposes everything
match ':controller(/:action(/:id))', via: [:get, :post]

# SECURE: Explicit routes only
Rails.application.routes.draw do
  resources :articles, only: [:index, :show]
  resources :comments, only: [:create]
  # Everything else returns 404
end
```

### Route Injection (CVE-2016-2098)

```ruby
# VULNERABLE: User-controlled route params in render
class DocumentsController < ApplicationController
  def show
    # CVE-2016-2098: RCE via render with user input
    render params[:template]  # ANY: /documents/1?template=file:///etc/passwd
  end
end

# SECURE: Restrict render params
class DocumentsController < ApplicationController
  VALID_TEMPLATES = %w[standard compact detailed].freeze

  def show
    template = params[:template].presence_in(VALID_TEMPLATES) || 'standard'
    render "documents/#{template}"
  end
end
```

**Reference**: [CVE-2016-2098 — HackerOne Report #113928](https://hackerone.com/reports/113928)

---