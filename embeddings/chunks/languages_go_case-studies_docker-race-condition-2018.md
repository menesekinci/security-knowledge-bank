---
source: "languages/go/case-studies/docker-race-condition-2018.md"
title: "Go Race Condition (2018) — Docker/Predictable UID"
category: "case-study"
language: "go"
severity: "critical"
tags: [case-study, cause, go, happened, impact, root, system, target, what, when]
---

# Go Race Condition (2018) — Docker/Predictable UID

## 📅 When Did It Happen?
2018 (CVE-2018-15664)

## 🎯 Target System
Docker Engine — container runtime written in Go

## 🔴 What Happened?
A **TOCTOU (Time-of-Check Time-of-Use)** race condition was found in Docker's `docker cp` command.
- When copying files from a container with `docker cp`, Docker first checks the file (check), then copies it (use)
- Between these two operations, an attacker can swap a symbolic link
- Result: writing files from inside the container to the host filesystem → **privilege escalation**

## 🧠 Root Cause (Go)
```go
// Simplified Docker cp:
func copyFromContainer(container string, src string, dst string) {
    // 1. CHECK: Validate the file (could take seconds)
    info, _ := os.Stat(src)  // At this point src = "/container/secret.txt"
    
    // *** RACE WINDOW: Symbolic link can be changed here! ***
    
    // 2. USE: Copy the file
    data, _ := os.ReadFile(src)  // src is now "/host/etc/shadow"!
    os.WriteFile(dst, data, 0644)
}
```

## 💥 Impact
- Privilege escalation from container to host
- All platforms using Docker were affected (Kubernetes, AWS ECS, etc.)
- Fortunately, it was fixed before being exploited (proactive security research)

## 🎓 Lessons Learned
- **Race conditions happen in Go too** — use `sync.Mutex` and atomic operations
- **TOCTOU** — close the gap between Check and Use
- **Prefer atomic APIs for file operations** (`os.Rename` is atomic)
- **Race conditions in Docker** — container accessing the host

## Vibe Coding Connection
When AI generates Go code:
- Race conditions are generally something AI overlooks
- Add "perform race condition check" to your prompt
- Test with `go test -race`

## 🔗 Source
- CVE-2018-15664: https://nvd.nist.gov/vuln/detail/CVE-2018-15664
- https://www.openwall.com/lists/oss-security/2019/05/28/1
