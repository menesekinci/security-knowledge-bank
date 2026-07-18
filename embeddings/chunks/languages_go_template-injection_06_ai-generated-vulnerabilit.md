---
source: "languages/go/template-injection.md"
title: "Template Injection — html/template Misuse, text/template RCE"
heading: "AI-Generated Vulnerability: Template Functions Expose Unsafe Operations"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [ai-generated, go, language-vuln, overview, vulnerability]
chunk: 6/10
---

## AI-Generated Vulnerability: Template Functions Expose Unsafe Operations

```go
// AI-GENERATED — template function map exposes unsafe operations
funcMap := template.FuncMap{
    "readFile": ioutil.ReadFile, // BUG: Templates can read any file!
    "exec":     execCommand,      // BUG: Templates can run commands!
    "lookupEnv": os.Getenv,       // BUG: Information disclosure
}

tmpl, _ := template.New("page").Funcs(funcMap).Parse(`
    Config: {{lookupEnv "DB_PASSWORD"}}
`)
```

**Secure Fix**: Restrict template functions to only what's needed.
```go
funcMap := template.FuncMap{
    "formatDate": time.Format,
    "upper":      strings.ToUpper,
    "safeURL":    func(s string) template.URL { return template.URL(s) },
    // Only expose deterministic, safe pure functions
}
```