# Go Modules Supply Chain — proxy.golang.org and MVS

## Overview

Go has a unique approach to dependency management compared to npm, pip, or Cargo. Go modules use **Minimal Version Selection (MVS)**, a `go.sum` file for checksum verification, and a default proxy (`proxy.golang.org`) maintained by Google. Despite these safeguards, the Go supply chain has real vulnerabilities that AI-generated code frequently ignores or exacerbates.

## How Go Module Security Works

- **`go.sum`**: Contains cryptographic hashes of every dependency version. `go mod verify` checks these.
- **`proxy.golang.org`**: Google's module mirror caches immutable module versions, preventing availability attacks on upstream VCS.
- **`SUM database`** (`sum.golang.org`): A transparent, append-only checksum database that ensures you get the same bits as everyone else.
- **Minimal Version Selection**: Picks the lowest compatible version, reducing the surface for "latest version" attacks.

## AI-Generated Vulnerability: No Version Pinning

```go
// AI-GENERATED go.mod (partial) — no constraints
module myapp

go 1.22

require (
    github.com/gin-gonic/gin v0.0.0-00010101000000-000000000000 // BUG: Pseudo-version!
    // or worse:
    github.com/somepackage v1.0.0 // But the module path doesn't exist!
)
```

**Problems**:
1. **Hallucinated modules**: AI may suggest module paths that don't exist. Attackers monitor for this.
2. **Missing indirect deps**: AI omits `// indirect` comments, causing incomplete dependency tracking.
3. **No `go.sum`**: AI-generated code often lacks a `go.sum` file, meaning integrity is unchecked.

## Attack Vectors

### 1. Module Path Hijacking

If a module path is a repository that no longer exists, an attacker can register it:

```go
// AI suggests: github.com/deadbeef/old-library v1.0.0
// The original repo was deleted. Attacker creates github.com/deadbeef/old-library
// with a backdoored version. go get resolves to the attacker's code.
```

**MITRE ATT&CK technique**: T1195.001 (Supply Chain Compromise: Compromise Software Dependencies)

### 2. Typosquatting

Go module paths are case-sensitive on case-sensitive filesystems but not on all VCS hosts:

```
Valid:   github.com/gin-gonic/gin
Typos:   github.com/gin-gonicc/gin
         github.com/gin-gonice/gin
         github.com/gin-gonic/gin-helper (looks related, isn't)
```

### 3. Proxy Cache Poisoning (Theoretical)

While `proxy.golang.org` enforces immutability, a compromised proxy could serve different code. GONOSUMCHECK bypasses verification.

### 4. Vendor Directory Manipulation

```go
// AI-GENERATED — uses vendoring without verification
// go mod vendor creates a vendor/ directory
// If an attacker modifies files in vendor/, go build uses them
// AI-generated CI often lacks: go mod verify
```

## AI-Generated Vulnerability: Unnecessary Dependencies

```go
// AI-GENERATED — pulls in heavy dependencies for trivial operations
import (
    "github.com/sirupsen/logrus"     // For a single fmt.Println replacement
    "github.com/spf13/cobra"         // For a 2-arg CLI tool
    "github.com/go-sql-driver/mysql" // In a project that uses SQLite
    "gopkg.in/yaml.v3"               // Instead of encoding/json for config
)
```

Each unused dependency is an **additional attack surface**. AI code commonly imports 2-5x more modules than necessary.

## AI-Generated Vulnerability: Using `latest` or No Tag

```go
// AI-GENERATED go.mod — uses branch references
require (
    github.com/owner/repo v0.0.0-20230101000000-abcdef012345 // BUG: ephemeral pseudo-version
)

// OR: AI uses `replace` directive without understanding it:
replace github.com/owner/repo => ../local-fork // BUG: bypasses verification
```

**Risk**: Pseudo-versions point to specific commits, which is usually safe — but if the AI generates a pseudo-version that doesn't exist, `go build` fails or resolves differently.

## Defense: Go Module Security Tools

### 1. `go mod verify`

```bash
# Verifies that dependencies in go.sum match the downloaded modules
go mod verify
# Add to CI:
# - name: Verify module integrity
#   run: go mod verify
```

### 2. `go vet` + `staticcheck`

```bash
go vet ./...
staticcheck ./...
```

### 3. `gosec` and `nancy`

```bash
# gosec catches code-level vulnerabilities
gosec ./...

# Nancy scans go.sum against known CVEs
nancy go.sum
```

### 4. `dependabot` / `renovate`

Configure automated dependency updates with critical patch focus:

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
```

### 5. `govulncheck` (Official)

```bash
# Go team's official vulnerability checker
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

## The GONOSUMCHECK and GONOSUMDB Danger

```go
// AI-GENERATED Dockerfile or CI config — disables verification
ENV GONOSUMCHECK=*    // BUG: Skips checksum verification for ALL modules
ENV GONOSUMDB=*       // BUG: Skips checksum database lookup
ENV GOFLAGS=-mod=mod  // Auto-fixes go.mod — may silently add unexpected deps
```

**Never set `GONOSUMCHECK=*` or `GONOSUMDB=*` in production environments.**

## Real CVEs and Incidents

- **2023: left-pad style deletion on GitHub**: Multiple Go module repositories were deleted by their owners, breaking builds for dependent projects. While the Go proxy cache mitigated the impact, it highlighted the risk of external VCS dependencies.
- **CVE-2024-34158 (go/build/constraint, stdlib)**: Denial of service via stack exhaustion — the `Parse` function panics on build-constraint (`//go:build`) lines containing deeply nested expressions. CVSS 7.5, fixed in Go 1.22.7 / 1.23.1. It is flagged by `govulncheck`, illustrating that the Go vulnerability database is itself a critical supply-chain protection.
- **CVE-2023-39325 (golang.org/x/net/http2)**: This `x/net` vulnerability affected thousands of Go applications. The fix was automatically flagged by `govulncheck`, demonstrating the importance of running it in CI.

## Prevention Checklist

1. **Run `go mod verify` in CI** — Verifies checksums match.
2. **Run `govulncheck ./...` in CI** — Detects known vulnerabilities in all modules.
3. **Use `go.sum`** — Never commit a module without its `go.sum`.
4. **Pin major versions** — Specify major version in `go.mod`: `github.com/gin-gonic/gin v1.x`.
5. **Review `go get` additions from AI** — Audit every new dependency AI introduces.
6. **Use a private module proxy** — For enterprise, host `goproxy` or use `athens` to control which modules are available.
7. **Scan for known malicious modules** — Use `nancy` or `socket.dev` for Go.
8. **Never set `GONOSUMCHECK=*`** — This disables integrity verification.
9. **Minimize dependencies** — Favor stdlib over external packages. AI adds unnecessary deps.
10. **Use `go mod tidy`** — Removes unused dependencies from `go.mod`.
