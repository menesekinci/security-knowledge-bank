---
source: "languages/go/template-injection.md"
title: "Template Injection — html/template Misuse, text/template RCE"
heading: "AI-Generated Vulnerability: User-Controlled Template Content"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [ai-generated, go, language-vuln, overview, vulnerability]
chunk: 5/10
---

## AI-Generated Vulnerability: User-Controlled Template Content

This is the most dangerous pattern — allowing users to write template code:

```go
// AI-GENERATED — user controls template content
import "text/template"

func renderUserTemplate(w http.ResponseWriter, r *http.Request) {
    userTemplate := r.URL.Query().Get("template")
    
    tmpl, err := template.New("user").Parse(userTemplate)
    if err != nil {
        http.Error(w, "Bad template", http.StatusBadRequest)
        return
    }
    
    // RCE! User can write: {{.Execute "cat /etc/passwd"}}
    tmpl.Execute(w, nil)
}
```

**With `text/template`**, the user can invoke template functions that access the filesystem:
```
{{"file" | readFile}}       // If readFile is registered as a function
{{Exec "cat /etc/passwd"}}  // If Exec is registered (common in config templates)
```

**Even without custom functions**, `text/template` allows:
```
{{.Xss}}  // Dot access to nil receiver causes panic (DoS)
```

**Secure Fix**: Never accept template source code from users. If you need user-customizable templates, use a sandboxed engine or strict allowlisting.