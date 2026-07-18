---
source: "languages/ruby/rails-security.md"
title: "💎 Ruby on Rails Security — Complete Guide"
heading: "3. ActiveStorage Security"
category: "language-vuln"
language: "ruby"
severity: "medium"
tags: [actionmailer, activestorage, csrf, escaping, injection, language-vuln, protection, route, ruby, security]
chunk: 4/10
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