---
source: "common/api-security/graphql-security.md"
title: "GraphQL Security"
heading: "6. CVEs & Real-World Examples"
category: "api-security"
language: "common"
severity: "medium"
tags: [api-security, attacks, batching, depth, introspection, leaks, overview, query, table]
chunk: 9/10
---

## 6. CVEs & Real-World Examples

### CVE-2024-50312 — GraphQL Introspection Improper Access Control
- **Description**: Vulnerability in GraphQL due to improper access controls on the introspection query, allowing unauthorized users to enumerate the entire schema, discover hidden fields, and plan targeted attacks
- **Affected**: Multiple GraphQL implementations
- **CVSS**: 5.3 (Medium)
- **Fix**: Disable introspection in production; implement schema-allow-list for internal tools
- **Source**: https://nvd.nist.gov/vuln/detail/CVE-2024-50312

### CVE-2024-40094 — graphql-java Introspection Denial of Service
- **Description**: GraphQL Java fails to account for ExecutableNormalizedFields (ENFs) when preventing DoS; a crafted introspection query with deeply nested aliases forces excessive CPU/memory work and can exhaust the server
- **Affected**: graphql-java before 21.5 (also fixed in 20.9 and 19.11)
- **CVSS**: 5.3 (Medium, CVSS 3.1) / 8.7 (CVSS 4.0)
- **Fix**: Upgrade graphql-java to 21.5+ (or 20.9 / 19.11); enforce query depth/complexity limits and restrict introspection
- **Source**: https://nvd.nist.gov/vuln/detail/CVE-2024-40094

### GraphQL Batching Attack — Facebook/Rewards Bypass (HackerOne)
- **Description**: Researcher discovered that a GraphQL endpoint allowed batch queries to perform credential stuffing attacks with 50+ login attempts in a single HTTP request, bypassing per-request rate limits
- **Bounty**: $3,000
- **Fix**: Implement per-operation rate limiting; limit batch size; disallow batched mutations
- **Source**: https://medium.com/@amindaimond1/graphql-batching-attacks-my-wild-ride-into-modern-api-vulnerabilities-4161b888dead

### Shopify GraphQL Information Disclosure (Assetnote research — no CVE)
- **Description**: Improper field-level authorization in GraphQL resolvers allowed authenticated users to query metadata about resources they should not have access to, via indirect relationship traversal
- **Affected**: Shopify GraphQL API (bug-bounty / research finding, no assigned CVE)
- **Fix**: Implement field-level authorization in all resolvers, not just top-level queries
- **Source**: https://www.assetnote.io/resources/research/exploiting-graphql

---