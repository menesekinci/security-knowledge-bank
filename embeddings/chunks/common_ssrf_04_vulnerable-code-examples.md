---
source: "common/ssrf.md"
title: "Server-Side Request Forgery (SSRF)"
heading: "Vulnerable Code Examples"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [cloud, code, common-vuln, fixed, metadata, vibe, vulnerable, what]
chunk: 4/10
---

## Vulnerable Code Examples

**Node.js (Express) — Vulnerable**
```javascript
const axios = require('axios');

app.get('/fetch-profile', async (req, res) => {
    const imageUrl = req.query.url;
    // 🔴 VULNERABLE: fetches any URL
    const response = await axios.get(imageUrl);
    res.send(response.data);
});
// Attack: /fetch-profile?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
// Returns AWS credentials from metadata endpoint!
```

**Python (Flask) — Vulnerable**
```python
import requests

@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    # 🔴 VULNERABLE: fetches any URL
    resp = requests.get(url)
    return resp.content
```

**Ruby on Rails — Vulnerable**
```ruby
def fetch_avatar
  url = params[:url]
  # 🔴 VULNERABLE
  response = HTTP.get(url)
  send_data response.body
end
```