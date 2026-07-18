---
source: "common/cloud-security/aws-security.md"
title: "AWS Security"
heading: "5. CVEs & Real-World Examples"
category: "cloud-security"
language: "common"
severity: "medium"
tags: [bucket, cloud-security, lambda, least, overview, security, table]
chunk: 8/9
---

## 5. CVEs & Real-World Examples

### CVE-2025-14764 — Amazon S3 Encryption Client Key Confusion
- **Description**: Missing cryptographic key commitment in the Amazon S3 Encryption Client for Go. A user with write access to the S3 bucket could introduce a new encryption data key (EDK) that decrypts to different plaintext — effectively a key confusion attack
- **Affected**: Amazon S3 Encryption Client for Go, .NET
- **CVSS**: 7.4 (High)
- **Fix**: Upgrade to versions with cryptographic key commitment support
- **Source**: https://nvd.nist.gov/vuln/detail/CVE-2025-14764

### CVE-2025-23206 — AWS CDK IAM OIDC Provider MITM (Unverified TLS)
- **Description**: The AWS CDK IAM OIDC custom-resource provider downloads the identity provider's CA thumbprint using `tls.connect` with `rejectUnauthorized: false` hardcoded. Because the TLS certificate is never validated, a man-in-the-middle can impersonate the OIDC provider and have the CA thumbprint pinned to an attacker-controlled endpoint. (Not "information disclosure in template outputs" — the earlier write-up was wrong.)
- **Affected**: `aws-cdk-lib` before 2.177.0 (IAM OIDC custom-resource provider)
- **CVSS**: Low — the AWS CDK advisory (CNA, GHSA-v4mq-x674-ff73) rates it CVSS 4.0 = 1.8 Low, because the issuer URL is defined by the CDK author and the code runs inside a Lambda environment that mitigates MITM. (NVD adopted an inflated 8.1 High primary score; CWE-347, Improper Verification of Cryptographic Signature.)
- **Fix**: Upgrade to CDK ≥ 2.177.0 and set the feature flag `@aws-cdk/aws-iam:oidcRejectUnauthorizedConnections` to `true` in `cdk.json`/`cdk.context.json`
- **Source**: https://github.com/aws/aws-cdk/security/advisories/GHSA-v4mq-x674-ff73

### Public S3 Bucket Data Leak — "AWS S3 Bucket Slippage" (Ongoing)
- **Description**: Continual stream of data breaches from misconfigured S3 buckets. In 2025 alone, over 200 million records were exposed through publicly accessible S3 buckets. Notable examples include healthcare records, voter databases, and internal source code
- **Fix**: Enable S3 Block Public Access at account level; use AWS Config rules to detect and auto-remediate public buckets
- **Source**: https://docs.prismacloud.io/en/enterprise-edition/rn/prisma-cloud-release-info/features-introduced-in-2025/features-introduced-in-february-2025

### CISA AWS GovCloud Key Leak (2025)
- **Description**: A CISA administrator leaked AWS GovCloud plaintext credentials on GitHub via a private repository that should have been .gitignored. The exposed keys gave access to critical CISA GovCloud resources
- **Impact**: Sensitive government cloud infrastructure potentially compromised
- **Fix**: Enforce git-secrets scanning; use IAM Access Analyzer; rotate credentials immediately upon discovery
- **Source**: https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/

### AWS Lambda Command Injection (Common Bug Bounty Finding)
- **Description**: Lambda functions that construct shell commands from event parameters are a common high-severity bug bounty finding. Even when input validation appears solid, edge cases in shell quoting and parameter expansion can bypass filters
- **Fix**: Never use `shell=True` in subprocess calls; use SDKs instead of shell commands; validate all inputs against an allow list
- **Source**: https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html

### CVE-2025-4802 — glibc `LD_LIBRARY_PATH` Untrusted Search Path (setuid dlopen)
- **Description**: An untrusted `LD_LIBRARY_PATH` environment-variable vulnerability in the GNU C Library (glibc). In statically-compiled **setuid** binaries that call `dlopen` (including internal `dlopen` calls after `setlocale` or NSS functions), an attacker-controlled `LD_LIBRARY_PATH` can force loading of an attacker-supplied shared library, leading to local privilege escalation. This is a glibc flaw — it surfaces in Lambda/container base images only because they ship the affected glibc, not a Lambda-specific bug.
- **Affected**: glibc 2.27 through 2.38 (shipped by many Linux base images, including some Lambda/container runtimes)
- **CVSS**: 7.8 (High) — CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H (CWE-426, Untrusted Search Path)
- **Fix**: Patch glibc (≥ 2.39, or distro backports); rebuild container/Lambda images against patched base images; use image scanning
- **Source**: https://nvd.nist.gov/vuln/detail/CVE-2025-4802

---