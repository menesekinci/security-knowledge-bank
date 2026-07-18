---
source: "common/api-security/grpc-security.md"
title: "gRPC Security"
heading: "5. CVEs & Real-World Examples"
category: "api-security"
language: "common"
severity: "medium"
tags: [api-security, message, mtls, overview, reflection, size, table]
chunk: 8/9
---

## 5. CVEs & Real-World Examples

### CVE-2024-11407 — gRPC-C++ Zero-Copy Data-Corruption DoS
- **Description**: On gRPC-C++ servers with transmit zero-copy enabled (`GRPC_ARG_TCP_TX_ZEROCOPY_ENABLED`), application data can be corrupted before transmission, so the receiver gets an incorrect byte set and RPC requests fail — a denial of service via data corruption (CWE-682 Incorrect Calculation, not a TLS/info-disclosure issue)
- **Affected**: gRPC-C++ with TCP TX zero-copy enabled
- **CVSS**: 6.9 (Medium, CVSS 4.0)
- **Fix**: Upgrade to a patched gRPC release
- **Source**: https://github.com/advisories/GHSA-p9rf-64qj-22rw

### gRPC Reflection Information Disclosure (Multiple Reports)
- **Description**: Numerous penetration tests and bug bounty reports cite enabled gRPC reflection in production as a critical finding. Attackers use grpcurl or similar tools to enumerate all available services, methods, and message schemas
- **Affected**: Any production gRPC service with reflection enabled
- **Fix**: Disable reflection in production; use service mesh (e.g., Istio) for internal discovery
- **Source**: https://www.stackhawk.com/blog/best-practices-for-grpc-security/

### GO-2024-2687 — gRPC Example Code HTTP/2 Vulnerability
- **Description**: Example code in zitadel-go v3 library was impacted by HTTP/2 protocol vulnerabilities that could lead to stream multiplexing attacks
- **Affected**: zitadel-go v3 library, gRPC-example components
- **CVSS**: 7.5 (High)
- **Fix**: Update to patched versions; avoid using example code in production without review
- **Source**: https://github.com/zitadel/zitadel-go/security/advisories/GHSA-qc6v-5g5m-8cw2

### CVE-2023-44487 — HTTP/2 Rapid Reset Attack
- **Description**: Rapid reset attack on HTTP/2 streams, affecting gRPC over HTTP/2. Allows attackers to send rapid stream resets causing DoS
- **Affected**: Multiple gRPC implementations (C-core, Go, Java)
- **CVSS**: 7.5 (High)
- **Fix**: Apply patches from gRPC ecosystem; limit stream reset rate; upgrade to fixed versions
- **Source**: https://nvd.nist.gov/vuln/detail/CVE-2023-44487

### gRPC Message Size DoS (No CVE — Common Pattern)
- **Description**: Without enforced message size limits, attackers send large protobuf messages causing OOM on server. Multiple bug bounty reports cite this as a common finding in gRPC services
- **Fix**: Enforce `MaxRecvMsgSize` and `MaxSendMsgSize` at server initialization
- **Source**: https://www.stackhawk.com/blog/best-practices-for-grpc-security/

---