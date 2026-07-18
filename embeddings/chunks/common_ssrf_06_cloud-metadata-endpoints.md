---
source: "common/ssrf.md"
title: "Server-Side Request Forgery (SSRF)"
heading: "Cloud Metadata Endpoints to Protect"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [cloud, code, common-vuln, fixed, metadata, vibe, vulnerable, what]
chunk: 6/10
---

## Cloud Metadata Endpoints to Protect

| Cloud | Metadata URL |
|---|---|
| AWS | http://169.254.169.254/latest/meta-data/ |
| GCP | http://metadata.google.internal/computeMetadata/v1/ |
| Azure | http://169.254.169.254/metadata/instance?api-version=2021-02-01 |
| DigitalOcean | http://169.254.169.254/metadata/v1.json |
| Alibaba | http://100.100.100.200/latest/meta-data/ |

**Attack pattern:** `ssrf-endpoint?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/admin`

---