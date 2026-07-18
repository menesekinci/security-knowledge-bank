---
source: "languages/go/ssrf.md"
title: "SSRF — net/http, Custom Transports, and Server-Side Request Forgery"
category: "language-vuln"
language: "go"
chunk: 4
total_chunks: 8
heading: "Vulnerable Code Examples"
---

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