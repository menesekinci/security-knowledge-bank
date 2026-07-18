# SSRF — net/http, Custom Transports, and Server-Side Request Forgery

## Overview

Server-Side Request Forgery (SSRF) occurs when an attacker can make a server-side application make HTTP requests to an arbitrary destination. In Go, SSRF vulnerabilities are common because the standard `net/http` client makes it trivially easy to send requests to any URL — and AI-generated code rarely validates URLs before making HTTP calls.

## How AI Generates SSRF in Go

LLMs frequently generate code that:
1. Accepts a URL from user input and directly passes it to `http.Get()`
2. Uses `http.Client` without timeout or redirect limits
3. Fetches resources from user-supplied file paths or domain names
4. Disables certificate verification (`InsecureSkipVerify: true`)

## Vulnerable Code Examples

### Pattern 1: Direct User-Controlled URL

```go
// AI-GENERATED — classic SSRF
func fetchURL(w http.ResponseWriter, r *http.Request) {
    targetURL := r.URL.Query().Get("url")
    
    // BUG: No validation! Attacker can pass:
    // 1. file:///etc/passwd
    // 2. http://169.254.169.254/latest/meta-data/  (AWS metadata)
    // 3. http://localhost:6379/ (internal Redis)
    // 4. http://internal-admin:8080/ (internal services)
    
    resp, err := http.Get(targetURL)
    if err != nil {
        http.Error(w, "Failed", http.StatusBadRequest)
        return
    }
    defer resp.Body.Close()
    
    io.Copy(w, resp.Body) // Returns internal data to attacker
}
```

**Secure Fix**: URL validation whitelist.
```go
import "net/url"

var allowedHosts = map[string]bool{
    "api.example.com": true,
    "cdn.example.com": true,
}

func fetchURL(w http.ResponseWriter, r *http.Request) ([]byte, error) {
    rawURL := r.URL.Query().Get("url")
    
    parsed, err := url.Parse(rawURL)
    if err != nil {
        return nil, fmt.Errorf("invalid URL")
    }
    
    // Block internal IPs
    if isPrivateIP(parsed.Hostname()) {
        return nil, fmt.Errorf("internal resources not allowed")
    }
    
    // Verify against whitelist
    if !allowedHosts[parsed.Hostname()] {
        return nil, fmt.Errorf("host not allowed")
    }
    
    // Only allow HTTPS
    if parsed.Scheme != "https" {
        return nil, fmt.Errorf("only HTTPS allowed")
    }
    
    // Now fetch
    resp, err := http.Get(parsed.String())
    // ...
}

func isPrivateIP(host string) bool {
    ip := net.ParseIP(host)
    if ip == nil {
        return false
    }
    return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}
```

### Pattern 2: No Redirect Restrictions

```go
// AI-GENERATED — follows redirects to internal services
func proxyRequest(w http.ResponseWriter, r *http.Request) {
    client := &http.Client{}
    // Default client follows up to 10 redirects
    // Attacker's URL: http://evil.com/redirect?to=http://169.254.169.254/
    // The server will follow the redirect to the internal IP!
}
```

**Secure Fix**: Restrict or disable redirects.
```go
client := &http.Client{
    CheckRedirect: func(req *http.Request, via []*http.Request) error {
        // Block redirects to private IPs
        if isPrivateIP(req.URL.Hostname()) {
            return fmt.Errorf("redirect to internal resource blocked")
        }
        if len(via) >= 3 {
            return fmt.Errorf("too many redirects")
        }
        return nil
    },
}
```

### Pattern 3: Custom Transport Without Restrictions

```go
// AI-GENERATED — custom transport without safeguards
func customFetch(w http.ResponseWriter, r *http.Request) {
    transport := &http.Transport{
        // BUG: Accepts any URL scheme, no dial restrictions
        // Allows file://, gopher://, dict://, etc.
    }
    
    client := &http.Client{Transport: transport}
    
    target := r.URL.Query().Get("url")
    resp, err := client.Get(target) // SSRF + scheme injection!
}
```

**Secure Fix**: Custom dialer with IP restrictions.
```go
import "golang.org/x/net/context"

func restrictedTransport() *http.Transport {
    dialer := &net.Dialer{
        Timeout:   5 * time.Second,
        KeepAlive: 30 * time.Second,
    }
    
    return &http.Transport{
        DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
            host, port, err := net.SplitHostPort(addr)
            if err != nil {
                return nil, err
            }
            
            ip := net.ParseIP(host)
            if ip == nil {
                // Resolve and check
                ips, err := net.DefaultResolver.LookupHost(ctx, host)
                if err != nil || len(ips) == 0 {
                    return nil, fmt.Errorf("could not resolve")
                }
                ip = net.ParseIP(ips[0])
            }
            
            if ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() {
                return nil, fmt.Errorf("blocked internal IP")
            }
            
            return dialer.DialContext(ctx, network, addr)
        },
    }
}
```

### Pattern 4: File Scheme Access

```go
// AI-GENERATED — allows file:// scheme
func serveFile(w http.ResponseWriter, r *http.Request) {
    // If AI code passes user input to http.Get with a file:// scheme:
    resp, err := http.Get("file:///etc/shadow") // Reads local files!
    // ...
}
```

**Fix**: Restrict schemes.
```go
func safeURL(rawURL string) (string, error) {
    parsed, err := url.Parse(rawURL)
    if err != nil {
        return "", err
    }
    
    if parsed.Scheme != "https" {
        return "", fmt.Errorf("only https scheme allowed")
    }
    
    // Reject raw IPs (usually suspicious in SSRF context)
    if net.ParseIP(parsed.Hostname()) != nil {
        return "", fmt.Errorf("IP addresses not allowed")
    }
    
    return parsed.String(), nil
}
```

## Advanced SSRF With Cloud Metadata

The most common SSRF target: cloud provider metadata endpoints.

| Cloud | Metadata URL |
|---|---|
| AWS | `http://169.254.169.254/latest/meta-data/` |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` |
| DigitalOcean | `http://169.254.169.254/metadata/v1.json` |

An SSRF that can reach these endpoints leaks IAM credentials, instance metadata, and potentially cloud API keys.

## Real CVEs

- **CVE-2022-39383 (KubeVela / VelaUX APIServer, CVSS 6.5)**: A **blind SSRF** in the VelaUX API server. When Helm Chart was used as a component delivery method, the warehouse (repository) request address was not restricted, so a low-privileged attacker could point it at internal resources and force the server to make requests on their behalf. Fixed in KubeVela 1.5.9 and 1.6.2.
- **CVE-2026-58404 (Hugo, CVSS 6.8)**: An **SSRF with cloud-metadata exposure**. Hugo's `security.http.urls` deny policy only blocked loopback, internal, and metadata addresses written in dotted-decimal IPv4 notation; alternate IPv4 encodings (integer, hexadecimal, octal) bypassed the check, letting `resources.GetRemote` reach blocked services — including `169.254.169.254` metadata endpoints — during template processing (dangerous in hosted/CI builds). Exactly the decimal-only-filter mistake this page warns about. Fixed in Hugo 0.163.1.

## Detection

```bash
# gosec catches InsecureSkipVerify (G402)
gosec -include G402 ./...

# Detect http.Get with user input:
grep -rn 'http\.\(Get\|Post\|Do\)' ./*.go

# Staticcheck catches some redirect issues
staticcheck -checks 'SA5000' ./...
```

## Prevention Checklist

1. **Validate and whitelist URLs** — Never pass user input directly to `http.Get()`.
2. **Restrict URL schemes** — Force HTTPS only; block `file://`, `gopher://`, `dict://`, `ftp://`.
3. **Block private and loopback IPs** — Use a custom `DialContext` that rejects `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`.
4. **Set timeouts** — `http.Client{Timeout: 5 * time.Second}` prevents slow-loris style SSRF.
5. **Restrict redirects** — Use `CheckRedirect` with max redirects and IP validation.
6. **Use a URL parser** — `net/url.Parse()` to validate before making requests.
7. **Log unusual request targets** — Alert on requests to metadata IPs or internal ranges.
8. **Use a dedicated HTTP client** — With restricted transport, never the default `http.DefaultClient`.
9. **Consider using a proxy** — Route all external requests through a forward proxy that enforces restrictions.
10. **Run `gosec`** — Detects unvalidated URL usage and weak transport controls.
