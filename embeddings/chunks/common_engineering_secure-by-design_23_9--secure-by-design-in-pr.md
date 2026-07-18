---
source: "common/engineering/secure-by-design.md"
title: "Secure by Design"
heading: "9. Secure by Design in Practice: A Worked Example"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [architecture, common-vuln, decision, requirements, secure, security, status, table, what]
chunk: 23/25
---

## 9. Secure by Design in Practice: A Worked Example

**Scenario:** Building a document-sharing platform — users upload PDFs and share them via links.

### Phase 1: Requirements (SbD from Sprint 1)

**Business requirements:**
- Users upload PDFs (up to 50 MB)
- Documents are shared via unique, unguessable links
- Only the uploader can delete a document

**Security requirements derived:**
- In-transit encryption (TLS) — all traffic
- At-rest encryption — PDF content encrypted in S3
- Access control — only the uploader can delete; anyone with the link can view
- Input validation — file type validation, virus scanning, path sanitization
- Audit log — every upload, share, and delete is logged

### Phase 2: Architecture Decisions

| Decision | Security Concern | Chosen Approach |
|---|---|---|
| File storage | Where does the PDF live? | S3 with bucket policies restricted to the application role |
| Link generation | How to make links unguessable? | 256-bit random tokens (crypto/rand), not sequential IDs |
| Download auth | How to authorize a download? | Token in URL = implicit authorization; no additional auth for viewers |
| Deletion auth | How to authorize a delete? | Uploader's JWT must match the owner stored with the document |
| Virus scanning | How to handle malicious uploads? | ClamAV scan on upload; reject if infected; scanned-async for large files |

### Phase 3: Design Patterns Applied

- **Guard pattern** on every `DeleteDocument` operation (owner check)
- **Proxy pattern** on the S3 download handler (verifies the share link is active and not expired)
- **Observer pattern** on upload and delete events (audit logging, notification to uploader)
- **Facade pattern** — `DocumentService` is the only public interface; S3 and database are internal

### Phase 4: Trade-offs

| Trade-off | Decision | Rationale |
|---|---|---|
| Link sharing vs auth | No auth on view — anyone with the link can see the doc | Business requirement; mitigated by link unpredictability and optional expiry |
| File scanning latency | Upload response time vs security | Accept higher latency for all files up to 10 MB; async scan for 10–50 MB files |
| Encryption at rest | Server-side vs client-side encryption | Server-side with KMS; client-side adds complexity and prevents server-side search/indexing |

### Phase 5: Secure Defaults

- All new buckets are private by default
- Share links default to expiring in 7 days (configurable, never "never expires")
- Upload endpoint defaults to 10 MB limit with explicit override
- All audit logging is enabled by default and cannot be disabled by tenants

---