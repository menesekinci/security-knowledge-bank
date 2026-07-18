---
source: "languages/go/template-injection.md"
title: "Template Injection — html/template Misuse, text/template RCE"
category: "language-vuln"
language: "go"
chunk: 10
total_chunks: 10
heading: "Prevention Checklist"
---

## Prevention Checklist

1. **Always use `html/template` for HTML** — Never `text/template` when generating HTML.
2. **Never disable escaping** — Avoid `template.HTML`, `template.JS`, `template.URL`, `template.CSS` with user input.
3. **Never parse user-supplied template source** — This is RCE with `text/template`.
4. **Restrict `template.FuncMap`** — Only expose pure, deterministic, safe functions.
5. **Sanitize HTML before marking as safe** — Use `bluemonday` or similar HTML sanitizer.
6. **Use `text/template` only for trusted content** — Config file generation, code generation from trusted templates.
7. **Run `gosec`** — It catches G203 (unescaped template data).
8. **Audit all `template.FuncMap` for unsafe operations** — File I/O, exec, env access.
9. **Use `template.Must` carefully** — Panics at runtime on parse errors, causing DoS.