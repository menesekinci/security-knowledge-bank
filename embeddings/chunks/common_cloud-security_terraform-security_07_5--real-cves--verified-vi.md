---
source: "common/cloud-security/terraform-security.md"
title: "Terraform & OpenTofu IaC Security Deep Dive"
heading: "5. Real CVEs (Verified via NVD)"
category: "cloud-security"
language: "common"
severity: "high"
tags: [cloud-security, code, explanation, overview, secure, vulnerability, vulnerable]
chunk: 7/11
---

## 5. Real CVEs (Verified via NVD)

### CVE-2018-9057 — Weak IAM Password Generation (AWS Provider)
- **Published:** 2018-03-27
- **CVSS:** 9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **CWE:** CWE-332 (Insufficient Entropy in PRNG)
- **Affected:** Terraform AWS provider <= 1.12.0
- **Description:** The `aws_iam_user_login_profile` resource in the AWS provider used an inappropriate PRNG algorithm and seeding for generating IAM login passwords. The generated passwords had insufficient entropy, making them predictable to remote attackers who can enumerate IAM users. An attacker who knows the password generation algorithm and seeding can compute the password for newly created IAM users.
- **Fix:** Upgrade to AWS provider > 1.12.0, which uses a cryptographically secure PRNG.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2018-9057

### CVE-2019-19316 — Cleartext State Transmission (Azure Backend)
- **Published:** 2019-12-02
- **CVSS:** 7.5 HIGH (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
- **CWE:** CWE-319 (Cleartext Transmission of Sensitive Information)
- **Affected:** Terraform < 0.12.17
- **Description:** When using the Azure backend with a Shared Access Signature (SAS) token, Terraform transmits the SAS token and state snapshot over cleartext HTTP instead of HTTPS. An attacker on the same network can intercept the SAS token (gaining access to the storage container) and the Terraform state (containing all infrastructure secrets).
- **Fix:** Upgrade to Terraform >= 0.12.17, which enforces HTTPS for Azure backend communication.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2019-19316

### CVE-2020-15511 — Terraform Enterprise Signup Bypass
- **Published:** 2020-07-30
- **CVSS:** 5.3 MEDIUM (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N)
- **Affected:** Terraform Enterprise <= v202006-1
- **Description:** Terraform Enterprise contained a default signup page that allowed user registration even when the organization disabled self-signup. This bypassed SAML enforcement, allowing unauthorized users to create accounts on the TFE instance.
- **Fix:** Upgrade to TFE >= v202007-1, which disables the signup page when SAML enforcement is enabled.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2020-15511

### CVE-2021-3153 — TFE 2FA Enforcement Bypass
- **Published:** 2021-03-26
- **CVSS:** 5.3 MEDIUM (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
- **CWE:** NVD-CWE-noinfo
- **Affected:** Terraform Enterprise <= v202102-2
- **Description:** Terraform Enterprise failed to enforce an organization-level setting that required all users within an organization to have two-factor authentication (2FA) enabled. Users could disable their own 2FA despite the organizational requirement.
- **Fix:** Upgrade to TFE >= v202103-1.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2021-3153

### CVE-2021-30476 — Vault Provider GCE Auth Misconfiguration
- **Published:** 2021-05-11
- **CVSS:** 9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) — NVD primary; CWE: NVD-CWE-noinfo
- **Affected:** Terraform Vault provider < 2.19.1
- **Description:** The `vault_gcp_auth_backend` resource did not correctly validate or configure GCE-type bound labels for Vault's GCP authentication method. This could allow a GCE instance with matching but unauthorized labels to authenticate to Vault.
- **Fix:** Upgrade to Vault provider >= 2.19.1.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2021-30476

### CVE-2020-13359 — GitLab Terraform API State Overwrite
- **Published:** 2020-11-19
- **CVSS:** 7.6 HIGH (AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:H/A:N)
- **Affected:** GitLab CE/EE 12.10+ to 13.5.2
- **Description:** The GitLab Terraform API exposed the object storage signed URL on the delete operation. A project maintainer could use this to overwrite the Terraform state file, bypassing audit controls and potentially corrupting or hijacking the managed infrastructure.
- **Fix:** Upgrade GitLab to >= 13.3.9, 13.4.5, or 13.5.2 depending on the release track.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2020-13359

### CVE-2021-36230 — TFE Privilege Escalation
- **Published:** 2021-08-10
- **CVSS:** 8.8 HIGH (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
- **Affected:** Terraform Enterprise <= v202106-1
- **Description:** Terraform Enterprise did not properly perform authorization checks on API requests executed using a run token. An attacker with a run token could escalate privileges to organization-level access, including modifying workspace settings and viewing sensitive variables.
- **Fix:** Upgrade to TFE >= v202107-1.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2021-36230

### CVE-2022-25374 — TFE Sensitive Data in HTTP Logs
- **Published:** 2022-03-25
- **CVSS:** 7.5 HIGH (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) — NVD primary
- **CWE:** CWE-532 (Insertion of Sensitive Information into Log File)
- **Affected:** Terraform Enterprise v202112-1 through v202201-2
- **Description:** Terraform Enterprise logged inbound HTTP request bodies in a manner that could capture sensitive data such as API tokens, variables, and run outputs. An attacker with access to the TFE server logs could extract secrets.
- **Fix:** Upgrade to TFE >= v202202-1, which sanitizes sensitive data from logs.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2022-25374

### CVE-2019-8944 — Octopus Deploy Terraform Variable Exposure
- **Published:** 2019-02-20
- **CVSS:** 6.5 MEDIUM (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
- **CWE:** CWE-532 (Insertion of Sensitive Information into Log File)
- **Affected:** Octopus Deploy < 2019.1.8
- **Description:** Octopus Deploy logged sensitive Terraform output variables during the deployment step. Remote authenticated users with access to deployment logs could view sensitive values (database passwords, API keys) that should have been restricted.
- **Fix:** Upgrade Octopus Deploy to >= 2019.1.8.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2019-8944

---