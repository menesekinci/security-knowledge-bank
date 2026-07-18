---
source: "languages/ruby/rails-security.md"
title: "💎 Ruby on Rails Security — Complete Guide"
heading: "2. View Escaping & XSS Prevention"
category: "language-vuln"
language: "ruby"
severity: "medium"
tags: [actionmailer, activestorage, csrf, escaping, injection, language-vuln, protection, route, ruby, security]
chunk: 3/10
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