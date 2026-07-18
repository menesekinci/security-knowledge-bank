---
source: "languages/python/side-channel.md"
title: "Side-Channel Risks in Python"
heading: "Additional Python Side-Channel Patterns"
category: "language-vuln"
language: "python"
severity: "medium"
tags: [additional, cve-2021-23336, cve-2023-50782, cve-2024-23342, language-vuln, overview, python, python-cryptography, python-ecdsa]
chunk: 6/8
---

## Additional Python Side-Channel Patterns

### Pattern 1: Boolean-Based Enumeration

```python
# VULNERABLE: Boolean oracle in user enumeration
def login(username, password):
    user = User.query.filter_by(email=username).first()
    if not user:
        return False, "User not found"  # Different message = oracle
    if not check_password(user, password):
        return False, "Invalid password"  # Different message
    return True, "Login successful"

# SECURE: Generic error message
def login_secure(username, password):
    user = User.query.filter_by(email=username).first()
    if not user:
        # Always "check" to normalize timing
        check_password_dummy(password)
        return False, "Invalid credentials"
    if not check_password(user, password):
        return False, "Invalid credentials"
    return True, "Login successful"
```

### Pattern 2: Timing Side-Channel in List Operations

```python
# VULNERABLE: 'in' operator on list vs set
def check_permission_vulnerable(user_id, allowed_users: list):
    # O(n) for lists — timing grows with position of match
    return user_id in allowed_users

# SECURE: Use set for O(1) consistent timing
def check_permission_secure(user_id, allowed_users: set):
    return user_id in allowed_users
```

### Pattern 3: Exception Content Leakage

```python
# VULNERABLE: Stack traces in API responses
from flask import Flask, jsonify

@app.errorhandler(Exception)
def handle_error(error):
    return jsonify({
        "error": str(error),  # Leaks file paths, SQL queries, etc.
        "traceback": traceback.format_exc()  # Full stack trace
    }), 500

# SECURE: Sanitized error responses
@app.errorhandler(Exception)
def handle_error_secure(error):
    # Log the full error internally
    app.logger.error(f"Internal error: {traceback.format_exc()}")
    # Return sanitized message
    return jsonify({
        "error": "An internal error occurred"
    }), 500
```

---