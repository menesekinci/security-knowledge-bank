# 💎 Ruby on Rails Security — Complete Guide

> **Category:** Languages / Ruby / Rails Specific
> **Last Updated:** July 2026
> **Description:** Comprehensive Rails security covering route security, view escaping, ActiveStorage, ActionMailer injection, and framework-specific vulnerabilities. Includes CVEs, vulnerable code patterns, and secure alternatives.

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

## 2. View Escaping & XSS Prevention

### Rails View Escaping by Default

Rails auto-escapes in ERB templates: `<%= user_input %>` is HTML-escaped. But there are bypasses:

```erb
<%# VULNERABLE: raw() bypasses escaping %>
<%= raw @user.bio %>

<%# VULNERABLE: html_safe bypasses escaping %>
<%= @user.bio.html_safe %>

<%# VULNERABLE: sanitize without options %>
<%= sanitize @user.bio %>  <!-- Allows <b>, <i>, <u>, <a> by default -->

<%# SECURE: Use default escaping %>
<%= @user.bio %>

<%# SECURE: Use strip_tags for plain text only %>
<%= strip_tags @user.bio %>

<%# SECURE: Use sanitize with strict allowlist %>
<%= sanitize @user.bio, tags: %w[b i em strong], attributes: [] %>
```

### XSS in JSON Endpoints

```ruby
# VULNERABLE: XSS via JSON API
render json: { message: @comment.body }
# If @comment.body is "<script>alert('xss')</script>"
# And the client renders it without escaping

# SECURE: Tell the client what to expect
render json: { message: @comment.body }, content_type: 'application/json'

# Alternatively, force escaping for HTML contexts
render json: { message: escape_once(@comment.body) }
```

### JavaScript Script Tag Injection

```erb
<%# VULNERABLE: Inline JS with interpolation %>
<script>
  var userName = '<%= @user.name %>';  <!-- XSS if name contains ' -->
</script>

<%# SECURE: Use escape_javascript %>
<script>
  var userName = '<%= escape_javascript(@user.name) %>';
</script>

<%# BEST: Use data attributes %>
<div data-user-name="<%= @user.name %>">  <!-- Safe, ERB escapes -->
<script>
  const userName = document.querySelector('[data-user-name]').dataset.userName;
</script>
```

---

## 3. ActiveStorage Security

### CVE-2025-24293 — ActiveStorage Transformation RCE

```ruby
# VULNERABLE (Rails < 7.1.5.2, < 7.2.2.2, < 8.0.2.1):
# User-supplied image transformation parameters
class PhotosController < ApplicationController
  def show
    @photo = Photo.find(params[:id])
    
    # CRITICAL: User controls transformation method!
    variant = @photo.variant(
      params[:transform] => params[:value]  # "resize_to_fill", "100x100>" etc.
    )
    send_data variant.processed.download
  end
end
```

**CVE-2025-24293 Details:**
- **Severity**: Critical (RCE via unsafe image transformation methods)
- **Affected**: Rails ≥ 5.2.0 with ActiveStorage + image_processing + mini_magick
- **Root Cause**: Unsafe transformation methods could be passed to mini_magick, leading to command injection
- **Fix**: Rails restricted allowed transformation methods to a safe set

**Secure Pattern:**

```ruby
# SECURE: Whitelist transformations
class PhotosController < ApplicationController
  ALLOWED_TRANSFORMS = {
    'thumb' => { resize_to_limit: [150, 150] },
    'medium' => { resize_to_limit: [300, 300] },
    'large' => { resize_to_limit: [800, 800] }
  }.freeze

  def show
    @photo = Photo.find(params[:id])
    variant_config = ALLOWED_TRANSFORMS[params[:size]] || ALLOWED_TRANSFORMS['medium']
    
    variant = @photo.variant(variant_config)
    send_data variant.processed.download
  end
end
```

**References**:
- [CVE-2025-24293 — ActiveStorage RCE](https://www.opswat.com/blog/critical-cve-2025-24293-in-ruby-on-rails-active-storage-rce-discovered-by-opswat-unit-515)
- [Rails Security Advisory](https://discuss.rubyonrails.org/t/cve-2025-24293-active-storage-allowed-transformation-methods-potentially-unsafe/89670)
- [GHSA-r4mg-4433-c7g3](https://github.com/advisories/GHSA-r4mg-4433-c7g3)

### ActiveStorage URL Security

```ruby
# VULNERABLE: Public ActiveStorage URLs without expiration
class User < ApplicationRecord
  has_one_attached :avatar
end

# Anyone with the URL can access — and they're guessable

# SECURE: Use expiring URLs
class User < ApplicationRecord
  has_one_attached :avatar
  
  def avatar_url
    avatar.url(expires_in: 1.hour)  # Temporary signed URL
  end
end

# SECURE: Redirect through controller with authorization
class AvatarsController < ApplicationController
  before_action :authenticate_user!
  
  def show
    @user = User.find(params[:user_id])
    authorize! :read, @user
    
    redirect_to @user.avatar.url(expires_in: 5.minutes)
  end
end
```

### ActiveStorage Content-Type Validation

```ruby
# VULNERABLE: No content type validation
class User < ApplicationRecord
  has_one_attached :avatar
end

# Attacker uploads .exe file as "avatar"

# SECURE: Validate content type in model
class User < ApplicationRecord
  has_one_attached :avatar
  
  validate :avatar_content_type
  
  private
  
  def avatar_content_type
    return unless avatar.attached?
    
    allowed_types = %w[image/jpeg image/png image/gif image/webp]
    unless avatar.content_type.in?(allowed_types)
      errors.add(:avatar, "must be an image (JPEG, PNG, GIF, or WebP)")
      avatar.purge
    end
  end
end
```

---

## 4. ActionMailer Injection

### CVE-2024-47889 — ActionMailer block_format ReDoS

```ruby
# VULNERABLE (Rails < 7.1.5.1, < 7.2.2.1):
# ActionMailer's block_format helper has a Redos vulnerability
class UserMailer < ApplicationMailer
  def notification(user, message)
    @message = message
    mail(to: user.email, subject: 'Notification')
  end
end

# In mailer view:
<%= block_format(@message) %>
# Crafted input causes catastrophic backtracking → ReDoS
```

**CVE-2024-47889 Details:**
- **Severity**: High (ReDoS)
- **Affected**: ActionMailer block_format helper
- **Root Cause**: Vulnerable regex in text formatting helper
- **Impact**: Denial of service via specially crafted email body text

**Secure Pattern:**

```ruby
# Instead of block_format, use simple_format with sanitization
<%= simple_format(h(@message)) %>

# Or manually handle with safer alternatives
<%= @message.split("\n").map { |line| h(line) }.join("<br>") %>
```

**References**:
- [CVE-2024-47889](https://nvd.nist.gov/vuln/detail/CVE-2024-47889)
- [Rails Security Announcements](https://discuss.rubyonrails.org/c/security-announcements/9)

### Mailer Header Injection

```ruby
# VULNERABLE: User input in email headers
class ContactMailer < ApplicationMailer
  def contact_form(name, email, message)
    @message = message
    # Header injection! User controls "name" → can inject Bcc, etc.
    mail(to: "support@example.com", 
         from: "#{name} <#{email}>",
         subject: "Contact from #{name}")
  end
end

# Attacker sends: name = "Spammer\nBcc: thousands@example.com"

# SECURE: Validate and encode headers
class ContactMailer < ApplicationMailer
  def contact_form(name, email, message)
    @message = message
    @sender_name = sanitize_header_value(name)
    
    mail(to: "support@example.com",
         from: email_address_with_name(email, @sender_name),
         subject: "Contact from #{@sender_name[0..50]}")
  end
  
  private
  
  def sanitize_header_value(value)
    value.to_s.strip.gsub(/[\r\n]/, ' ').truncate(100)
  end
end
```

### ERB Injection in Mailer Templates

```erb
<%# VULNERABLE: Raw user content in mailer template %>
<p>Dear <%= @user.name.html_safe %>,</p>

<%# If @user.name is "John <%= @password %>" → exposes user password %>
<%# SECURE: Always escape user data in mail templates %>
<p>Dear <%= @user.name %>,</p>  <!-- Rails auto-escapes this -->
```

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

## References

- [Ruby on Rails Security Guide](https://guides.rubyonrails.org/security.html)
- [CVE-2025-24293 — ActiveStorage RCE](https://nvd.nist.gov/vuln/detail/CVE-2025-24293)
- [CVE-2024-47889 — ActionMailer ReDoS](https://nvd.nist.gov/vuln/detail/CVE-2024-47889)
- [CVE-2016-2098 — Rails Render RCE](https://nvd.nist.gov/vuln/detail/CVE-2016-2098)
- [Brakeman — Rails Security Scanner](https://brakemanscanner.org/)
- [Rails Security Announcements](https://discuss.rubyonrails.org/c/security-announcements/9)
- [OWASP Ruby on Rails Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html)
