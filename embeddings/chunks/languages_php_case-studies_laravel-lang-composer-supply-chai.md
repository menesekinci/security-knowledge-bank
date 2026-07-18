---
source: "languages/php/case-studies/laravel-lang-composer-supply-chain-attack-2026.md"
title: "Laravel-Lang Composer Supply Chain Attack (May 2026)"
category: "case-study"
language: "php"
severity: "high"
tags: [affected, case-study, impact, indicators, overview, packages, php]
---

# Laravel-Lang Composer Supply Chain Attack (May 2026)

**Language:** PHP (Composer / Laravel Ecosystem)
**Vulnerability Type:** Supply Chain Attack (Git Tag Rewrite, CI/CD Secret Theft)
**Date:** May 22, 2026
**Packages Affected:** 4 packages, 600+ git tags rewritten

## Overview

On May 22, 2026, a single threat actor compromised **four popular Composer packages** maintained by the **Laravel-Lang** organization (the official Laravel translations packages). Rather than publishing a new malicious version, the attacker **rewrote every existing git tag** across all four repositories to point at malicious commits. Any developer running `composer update` or installing fresh versions would pull a payload that exfiltrates CI/CD secrets to an attacker-controlled domain.

This attack was particularly insidious because it poisoned **all versions** — old, new, and every one in between — making it impossible to "pin to a safe version."

## How the Attack Was Carried Out

### Step 1: Compromise

The attacker gained **push access to the Laravel-Lang GitHub organization** — likely via a compromised personal access token, OAuth app, or credential theft. All four repositories are almost certainly the work of one actor using **one compromised credential with org-wide push access**.

### Step 2: Tag Rewrite

Rather than publishing a new version, which might trigger security scanning or be noticeable, the attacker **force-pushed existing git tags** to point at new malicious commits:

- **laravel-lang/lang** — 502 tags rewritten (flagship package, first target)
- **laravel-lang/http-statuses** — all tags from v1.0.0 through v3.4.5
- **laravel-lang/actions** — all 46 tags from 1.0.0 through 1.12.2
- **laravel-lang/attributes** — all 86 tags

The rewrites happened in a **15-minute window** (22:32-00:00 UTC), confirming automated weaponization.

### Step 3: Payload Mechanism

The malicious commits added `src/helpers.php` to the Composer `autoload.files` map. Composer's `files` autoloading is **eager** — every listed file is `require`d the moment `vendor/autoload.php` is loaded. Since **every Laravel and Symfony application** calls `require __DIR__.'/vendor/autoload.php'` on startup, the payload fires automatically on every request.

### Step 4: Payload Behavior

The payload:
1. Reaches out to `flipboxstudio.info` (a typosquat of the legitimate `flipboxstudio.com`)
2. Downloads a hidden PHP loader and an ELF binary into `/tmp`
3. Exfiltrates **runner environment data** (CI/CD secrets, environment variables, API keys)
4. Self-deletes its own artifacts to frustrate forensics

After execution, only orphaned processes (a PHP process and an unnamed ELF binary with `ppid=1`) remain visible.

## Affected Packages

| Package | Tags Rewritten | Popularity |
|---------|---------------|------------|
| laravel-lang/lang | 502 tags | Flagship, millions of installs |
| laravel-lang/http-statuses | All (v1.0.0→v3.4.5) | Very popular |
| laravel-lang/actions | 46 tags | Widely used |
| laravel-lang/attributes | 86 tags | Widely used |

## Impact

- **CI/CD secret theft:** Any pipeline running `composer update` during the attack window had secrets exfiltrated
- **Any version is compromised:** Pinning to an older version doesn't help — every tag was overwritten
- **Supply chain propagation:** Anyone who installed compromised packages in the last few hours and pushed the result could inadvertently spread the attack

## Indicators of Compromise

- **C2 domain:** `flipboxstudio.info` (typosquat)
- **Stage 1:** `GET https://flipboxstudio.info/payload`
- **Stage 2:** `POST https://flipboxstudio.info/exfil`
- **Git commit author:** `Your Name <you@example.com>` on every malicious commit
- **Unique files:** `/tmp/.laravel_locale/<12 hex chars>.php` and `/tmp/.<8 hex chars>` (ELF binary)

## Key Takeaways for Developers

1. **Lock your dependencies.** `composer.lock` that pins exact commit SHAs would protect against tag rewrites — but only if the locked SHA is not a malicious one.
2. **Use package signatures / integrity checks.** Composer supports `composer.lock` checksums. Verify them.
3. **Monitor for unexpected tag changes.** If you're a maintainer, set up alerts for force-pushes to tags.
4. **Limit CI secret exposure.** Use OIDC-based authentication instead of long-lived secrets. Use environment-specific secrets with minimal scope.
5. **Egress control in CI.** Block outbound traffic to unknown domains from CI runners. Use tools like StepSecurity's Harden-Runner.

## References

- [StepSecurity - Laravel-Lang Supply Chain Attack](https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack)
- [Packagist - Composer Supply Chain Security](https://blog.packagist.com/an-update-on-composer-packagist-supply-chain-security/)
- [Laravel-Lang GitHub Organization](https://github.com/Laravel-Lang)
