---
source: "languages/ruby/rails-security.md"
title: "💎 Ruby on Rails Security — Complete Guide"
heading: "4. ActionMailer Injection"
category: "language-vuln"
language: "ruby"
severity: "medium"
tags: [actionmailer, activestorage, csrf, escaping, injection, language-vuln, protection, route, ruby, security]
chunk: 5/10
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