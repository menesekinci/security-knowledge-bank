# 🐹 Go net/http Security Deep Dive

## Request Smuggling (CVE-2025-22871)

HTTP request smuggling vulnerability in Go's `net/http` library.
- **Root cause:** `net/http` improperly accepted a **bare LF** (line feed, `\n` without a preceding `\r`) as a line terminator inside chunked-transfer chunk-size lines.
- When a Go server sits behind (or in front of) another server that treats that bare LF as part of a chunk extension, the two disagree on message boundaries — enabling request smuggling.
- **Fixed in Go 1.23.8 and 1.24.2** — the patched `net/http` accepts only CRLF for chunk-size lines, matching the HTTP/1.1 spec.

```go
// VULNERABLE (Go < 1.23.8 / < 1.24.2):
server := &http.Server{
    Addr: ":8080",
    // net/http accepts a bare LF in chunk-size lines → smuggling
}

// SECURE:
// Go 1.23.8+ / 1.24.2+ reject bare-LF chunk-size lines by default
```

## Host Header Injection

```go
// VULNERABLE:
func handler(w http.ResponseWriter, r *http.Request) {
    // r.Host may be under attacker control!
    link := fmt.Sprintf("https://%s/login", r.Host)
    // Host: evil.com → link: https://evil.com/login
}
```

## TLS Pitfalls

```go
// VULNERABLE:
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true, // 💀 NEVER in production!
        },
    },
}

// SECURE:
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            MinVersion: tls.VersionTLS12,
        },
    },
    Timeout: 10 * time.Second,
}
```

## CVE-2023-45288 — HTTP/2 CONTINUATION Flood
CONTINUATION-frame flood DoS in Go's HTTP/2 implementation (`net/http` and `golang.org/x/net/http2`). An attacker sends an endless stream of CONTINUATION frames; even after the headers exceed `MaxHeaderBytes` (so no memory is stored), every frame is still parsed and HPACK-decoded, letting a client force the server to burn CPU decoding arbitrarily large — often Huffman-encoded — header data for a request that will be rejected anyway. CVSS 7.5. Fixed in Go 1.21.9 / 1.22.2 and `golang.org/x/net/http2` v0.23.0, which cap the number of excess header frames before closing the connection.

**Source:**
- CVE-2025-22871: https://nvd.nist.gov/vuln/detail/CVE-2025-22871
- CVE-2023-45288: https://nvd.nist.gov/vuln/detail/CVE-2023-45288
