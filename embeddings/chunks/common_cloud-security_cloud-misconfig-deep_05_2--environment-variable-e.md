---
source: "common/cloud-security/cloud-misconfig-deep.md"
title: "Cloud Misconfiguration Deep Dive"
heading: "2. Environment Variable Exposure"
category: "cloud-security"
language: "common"
severity: "medium"
tags: [cloud, cloud-security, credential, environment, overview, table, variable]
chunk: 5/9
---

## 2. Environment Variable Exposure

Environment variables are a common place to store secrets, but they can be leaked through:

- **Process listing** (`/proc/self/environ` in containers)
- **Error messages** — stack traces that print env vars
- **Serverless cold start logs** — Lambda environment snapshotted
- **Debug endpoints** — `/debug/env` accidentally exposed

### Vulnerable Pattern (Env Var in Error Response)

```python
# VULNERABLE: Exposing env vars in error responses
from flask import Flask, jsonify
import os

app = Flask(__name__)

@app.route('/api/config')
def get_config():
    # DEBUG endpoint left in production!
    return jsonify({
        'DATABASE_URL': os.environ.get('DATABASE_URL'),  # Contains credentials!
        'API_KEY': os.environ.get('API_KEY'),
        'SECRET_KEY': os.environ.get('SECRET_KEY'),
    })

@app.errorhandler(Exception)
def handle_error(error):
    # VULNERABLE: Full exception details including env
    import traceback
    return jsonify({
        'error': str(error),
        'traceback': traceback.format_exc(),
        'environment': dict(os.environ)  # ALL env vars leaked!
    }), 500
```

### Secure Pattern (Sanitize Error Responses)

```python
# SECURE: Never expose env vars in responses
from flask import Flask, jsonify
import os
import logging

logger = logging.getLogger(__name__)

app = Flask(__name__)

# Whitelist of safe config values to expose
SAFE_CONFIG = {
    'APP_NAME': os.environ.get('APP_NAME', 'my-app'),
    'APP_VERSION': os.environ.get('APP_VERSION', 'unknown'),
    'ENVIRONMENT': os.environ.get('ENVIRONMENT', 'production'),
}

@app.route('/api/health')
def health():
    # Only expose safe, public config
    return jsonify({
        'status': 'ok',
        'config': SAFE_CONFIG  # No credentials here!
    })

@app.errorhandler(Exception)
def handle_error(error):
    # Log the full details for debugging
    logger.exception("Unhandled exception: %s", error)
    # Return generic message to client
    return jsonify({
        'error': 'An internal error occurred',
        'request_id': request.headers.get('X-Request-ID', 'unknown')
    }), 500
```

### Container Env Var Security

```dockerfile
# SECURE: Don't bake secrets into Docker images
FROM python:3.11-slim

# Build args are NOT persisted in final image
ARG BUILD_VERSION
ENV APP_VERSION=$BUILD_VERSION

# NEVER do this:
# ENV DATABASE_URL=postgresql://user:password@host/db
# ENV API_KEY=sk-live-abc123

# Use docker-compose or K8s secrets at runtime
COPY app/ /app
WORKDIR /app
CMD ["python", "app.py"]
```

```yaml
# docker-compose: Secrets from external file
version: '3.8'
services:
  app:
    build: .
    env_file: 
      - .env  # NOT committed to git
    # Better: use secrets
    secrets:
      - db_password
      - api_key

secrets:
  db_password:
    file: ./secrets/db_password.txt  # .gitignored
  api_key:
    file: ./secrets/api_key.txt
```

---