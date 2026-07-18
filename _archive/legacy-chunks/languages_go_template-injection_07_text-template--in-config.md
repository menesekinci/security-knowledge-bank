---
source: "languages/go/template-injection.md"
title: "Template Injection — html/template Misuse, text/template RCE"
category: "language-vuln"
language: "go"
chunk: 7
total_chunks: 10
heading: "`text/template` in Configuration Generation"
---

## `text/template` in Configuration Generation

Using `text/template` to generate config files for other services:

```go
// AI-GENERATED — text/template generates nginx config
// If user controls any template variable, they can inject config directives
tmpl, _ := template.New("nginx").Parse(`
server {
    listen 80;
    server_name {{.ServerName}};
    location / {
        proxy_pass http://{{.Backend}};
    }
}
`)
```

**Exploit**: If `.Backend` contains `127.0.0.1:8080; } server { listen 443;`, the attacker injects a new server block — potentially setting up a malicious reverse proxy.