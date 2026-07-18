---
source: "common/misconfiguration.md"
title: "Security Misconfiguration"
heading: "Fixed Configurations"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common, common-vuln, configurations, fixed, headers, misconfigurations, security, vibe, what]
chunk: 5/9
---

## Fixed Configurations

### Secure CORS
```javascript
// ✅ SECURE: specific origins
const allowedOrigins = ['https://app.mycompany.com', 'https://admin.mycompany.com'];
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 86400
}));
```

### Secure Headers (Helmet.js)
```javascript
// ✅ SECURE: use security header middleware
const helmet = require('helmet');
app.use(helmet());
// Sets: X-Content-Type-Options, X-Frame-Options, CSP, HSTS, etc.
```

### Secure File Uploads
```python
import os
import magic  # libmagic binding

ALLOWED_TYPES = {'image/jpeg', 'image/png', 'application/pdf'}
UPLOAD_DIR = '/secure/uploads'

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']

    # ✅ Validate file type by content (not extension)
    mime = magic.from_buffer(file.read(2048), mime=True)
    if mime not in ALLOWED_TYPES:
        return 'Invalid file type', 400

    # ✅ Use safe filename
    from werkzeug.utils import secure_filename
    filename = secure_filename(file.filename)
    file.save(os.path.join(UPLOAD_DIR, filename))
```

### Production-Ready Config
```python
# ✅ SECURE: environment-based config
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
```

---