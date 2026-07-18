#!/usr/bin/env python3
"""Append framework + extra sink rules; merge into semgrep-rules packs."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "semgrep-rules"

# Reuse dumper style from generate_quality_semgrep via import
import sys
sys.path.insert(0, str(ROOT / "scripts"))
from generate_quality_semgrep import (  # type: ignore
    rule,
    write_yaml,
    python_rules,
    javascript_rules,
    java_rules,
    go_rules,
    csharp_rules,
    c_rules,
    php_rules,
    ruby_rules,
    rust_rules,
    solidity_rules,
    typescript_rules,
    kotlin_rules,
    swift_rules,
    dangerous_builtin,
)


def framework_rules() -> list[dict]:
    return [
        # Django
        rule(
            "vibe-fw-django-raw-sql",
            "[VIBE-SEC][framework] Django raw SQL concatenation / extra(where=) risks. KB: languages/python/django-security.md",
            ["python"],
            pattern_either=[
                {"pattern": "cursor.execute(f\"...\")"},
                {"pattern": "cursor.execute(... % ...)"},
                {"pattern": ".$M.raw(f\"...\")"},
                {"pattern": ".$M.extra(where=[...])"},
            ],
            metadata={"cwe": "CWE-89", "kb_path": "languages/python/django-security.md", "framework": "django"},
        ),
        rule(
            "vibe-fw-django-mark-safe",
            "[VIBE-SEC][framework] mark_safe on dynamic content → XSS. KB: languages/python/django-security.md",
            ["python"],
            pattern="mark_safe(...)",
            metadata={"cwe": "CWE-79", "framework": "django"},
        ),
        rule(
            "vibe-fw-django-debug",
            "[VIBE-SEC][framework] DEBUG=True must not ship to production.",
            ["python"],
            severity="WARNING",
            pattern="DEBUG = True",
            metadata={"cwe": "CWE-489", "framework": "django"},
        ),
        # Flask
        rule(
            "vibe-fw-flask-debug",
            "[VIBE-SEC][framework] Flask debug mode enables interactive debugger / code exec risk.",
            ["python"],
            pattern_either=[
                {"pattern": "app.run(..., debug=True, ...)"},
                {"pattern": "app.run(debug=True)"},
                {"pattern": "app.config['DEBUG'] = True"},
            ],
            metadata={"cwe": "CWE-489", "framework": "flask"},
        ),
        rule(
            "vibe-fw-flask-render-string",
            "[VIBE-SEC][framework] render_template_string with user input → SSTI.",
            ["python"],
            pattern="render_template_string(...)",
            metadata={"cwe": "CWE-94", "framework": "flask", "kb_path": "languages/python/template-injection.md"},
        ),
        # Express
        rule(
            "vibe-fw-express-send-req",
            "[VIBE-SEC][framework] Sending raw request data can reflect XSS / open redirect.",
            ["javascript", "typescript"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "res.send(req.body)"},
                {"pattern": "res.send(req.query)"},
                {"pattern": "res.send(req.params)"},
                {"pattern": "res.redirect(req.query.$Q)"},
            ],
            metadata={"cwe": "CWE-79", "framework": "express"},
        ),
        rule(
            "vibe-fw-express-cors-star",
            "[VIBE-SEC][framework] CORS origin * with credentials.",
            ["javascript", "typescript"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "cors({origin: '*', credentials: true, ...})"},
                {"pattern": "cors({origin: \"*\", credentials: true, ...})"},
            ],
            metadata={"cwe": "CWE-942", "framework": "express"},
        ),
        # React
        rule(
            "vibe-fw-react-dangehtml",
            "[VIBE-SEC][framework] dangerouslySetInnerHTML XSS sink.",
            ["javascript", "typescript"],
            pattern="<... dangerouslySetInnerHTML={...} />",
            metadata={"cwe": "CWE-79", "framework": "react", "kb_path": "languages/javascript/react-security.md"},
        ),
        # Spring
        rule(
            "vibe-fw-spring-spel",
            "[VIBE-SEC][framework] SpEL parseExpression on untrusted input.",
            ["java"],
            pattern_either=[
                {"pattern": "new SpelExpressionParser().parseExpression(...)"},
                {"pattern": "(new SpelExpressionParser()).parseExpression(...)"},
            ],
            metadata={"cwe": "CWE-94", "framework": "spring"},
        ),
        rule(
            "vibe-fw-spring-actuator-expose",
            "[VIBE-SEC][framework] Review actuator exposure configuration.",
            ["java"],
            severity="WARNING",
            pattern_regex=r"management\.endpoints\.web\.exposure\.include\s*=\s*\*",
            metadata={"cwe": "CWE-200", "framework": "spring", "kb_path": "languages/java/spring-boot-actuator.md"},
        ),
        # EF / .NET
        rule(
            "vibe-fw-ef-fromsqlraw",
            "[VIBE-SEC][framework] FromSqlRaw/ExecuteSqlRaw with concatenation.",
            ["csharp"],
            pattern_either=[
                {"pattern": "FromSqlRaw($S + ...)"},
                {"pattern": "ExecuteSqlRaw($S + ...)"},
                {"pattern": "FromSqlRaw($\"...\")"},
            ],
            metadata={"cwe": "CWE-89", "framework": "efcore", "kb_path": "languages/csharp/sql-injection-ef.md"},
        ),
        # Rails
        rule(
            "vibe-fw-rails-where-sql",
            "[VIBE-SEC][framework] Rails where with string interpolation.",
            ["ruby"],
            pattern_either=[
                {"pattern": "where(\"...#{...}...\")"},
                {"pattern": "find_by_sql(\"...#{...}...\")"},
                {"pattern": "where(\"...\" + ...)"},
            ],
            metadata={"cwe": "CWE-89", "framework": "rails", "kb_path": "languages/ruby/sql-injection.md"},
        ),
        rule(
            "vibe-fw-rails-yaml-load",
            "[VIBE-SEC][framework] YAML.load unsafe deserialization.",
            ["ruby"],
            pattern="YAML.load(...)",
            metadata={"cwe": "CWE-502", "framework": "rails", "kb_path": "languages/ruby/yaml-deserialization.md"},
        ),
        # Nest/TS
        rule(
            "vibe-fw-ts-as-body",
            "[VIBE-SEC][framework] Casting request JSON with `as` skips validation.",
            ["typescript"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "(await $R.json()) as $T"},
                {"pattern": "$X as any"},
            ],
            metadata={"cwe": "CWE-20", "framework": "nestjs-next", "kb_path": "languages/typescript/zod-validation-bypass.md"},
        ),
        # Go templates
        rule(
            "vibe-fw-go-text-template",
            "[VIBE-SEC][framework] text/template without escaping in HTML contexts.",
            ["go"],
            severity="WARNING",
            pattern="template.New(...)",
            metadata={"cwe": "CWE-79", "framework": "stdlib", "kb_path": "languages/go/template-injection.md"},
        ),
        # Solidity OZ-ish
        rule(
            "vibe-fw-sol-tx-origin",
            "[VIBE-SEC][framework] tx.origin auth antipattern.",
            ["solidity"],
            pattern="tx.origin",
            metadata={"cwe": "CWE-346", "framework": "solidity", "kb_path": "languages/solidity/tx-origin.md"},
        ),
        rule(
            "vibe-fw-sol-delegatecall",
            "[VIBE-SEC][framework] delegatecall to dynamic target.",
            ["solidity"],
            severity="WARNING",
            pattern=".$X.delegatecall(...)",
            metadata={"cwe": "CWE-829", "framework": "solidity"},
        ),
        # PHP Laravel-ish
        rule(
            "vibe-fw-php-db-raw",
            "[VIBE-SEC][framework] DB::raw / whereRaw concatenation class.",
            ["php"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "DB::raw(...)"},
                {"pattern": "whereRaw(...)"},
                {"pattern": "selectRaw(...)"},
            ],
            metadata={"cwe": "CWE-89", "framework": "laravel"},
        ),
        # Joblib pickle path
        rule(
            "vibe-fw-joblib-load",
            "[VIBE-SEC][framework] joblib.load can execute pickle-like payloads.",
            ["python"],
            pattern="joblib.load(...)",
            metadata={"cwe": "CWE-502", "framework": "sklearn", "kb_path": "languages/python/pickle-rce.md"},
        ),
        rule(
            "vibe-fw-torch-load",
            "[VIBE-SEC][framework] torch.load weights_only=False historical RCE class.",
            ["python"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "torch.load(...)"},
                {"pattern": "torch.load(..., weights_only=False, ...)"},
            ],
            metadata={"cwe": "CWE-502", "framework": "pytorch"},
        ),
        # child_process / shell
        rule(
            "vibe-fw-node-exec",
            "[VIBE-SEC][framework] child_process exec family.",
            ["javascript", "typescript"],
            pattern_either=[
                {"pattern": "exec(...)"},
                {"pattern": "execSync(...)"},
                {"pattern": "child_process.exec(...)"},
            ],
            metadata={"cwe": "CWE-78", "framework": "node"},
        ),
        # Java ScriptEngine already partial — add Runtime
        rule(
            "vibe-fw-java-runtime-exec",
            "[VIBE-SEC][framework] Runtime.exec command injection sink.",
            ["java"],
            pattern="Runtime.getRuntime().exec(...)",
            metadata={"cwe": "CWE-78", "framework": "java-se"},
        ),
        # C# BinaryFormatter
        rule(
            "vibe-fw-binaryformatter",
            "[VIBE-SEC][framework] BinaryFormatter deserialize RCE class.",
            ["csharp"],
            pattern="new BinaryFormatter()",
            metadata={"cwe": "CWE-502", "framework": "dotnet", "kb_path": "languages/csharp/deserialization.md"},
        ),
        # PHP unserialize
        rule(
            "vibe-fw-php-unserialize",
            "[VIBE-SEC][framework] unserialize user data.",
            ["php"],
            pattern="unserialize(...)",
            metadata={"cwe": "CWE-502", "framework": "php", "kb_path": "languages/php/unserialize-rce.md"},
        ),
        # yaml.safe vs load already — add ruamel?
        rule(
            "vibe-fw-python-assert-security",
            "[VIBE-SEC][framework] assert used as security control (stripped with -O).",
            ["python"],
            severity="WARNING",
            pattern="assert $COND",
            metadata={"cwe": "CWE-617", "framework": "python"},
        ),
        # Next danger
        rule(
            "vibe-fw-next-public-secret",
            "[VIBE-SEC][framework] NEXT_PUBLIC_ env often leaks to client — review secrets.",
            ["javascript", "typescript"],
            severity="WARNING",
            pattern_regex=r"NEXT_PUBLIC_[A-Z0-9_]*(SECRET|KEY|TOKEN|PASSWORD)",
            metadata={"cwe": "CWE-312", "framework": "nextjs"},
        ),
        # path traversal classic
        rule(
            "vibe-fw-python-open-join",
            "[VIBE-SEC][framework] open(os.path.join(base, user)) without resolve jail.",
            ["python"],
            severity="WARNING",
            pattern="open(os.path.join(...), ...)",
            metadata={"cwe": "CWE-22", "kb_path": "languages/python/path-traversal.md"},
        ),
        rule(
            "vibe-fw-js-readfile-concat",
            "[VIBE-SEC][framework] fs.readFile with concatenated user path.",
            ["javascript", "typescript"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "fs.readFile(... + ..., ...)"},
                {"pattern": "fs.readFileSync(... + ..., ...)"},
                {"pattern": "readFile(... + ..., ...)"},
            ],
            metadata={"cwe": "CWE-22"},
        ),
        # SSRF classic requests.get(user)
        rule(
            "vibe-fw-python-requests-get",
            "[VIBE-SEC][framework] requests to user-controlled URL — SSRF review.",
            ["python"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "requests.get($URL)"},
                {"pattern": "requests.post($URL, ...)"},
                {"pattern": "urllib.request.urlopen($URL)"},
            ],
            metadata={"cwe": "CWE-918", "kb_path": "languages/python/ssrf-python.md"},
        ),
        rule(
            "vibe-fw-js-fetch-user",
            "[VIBE-SEC][framework] fetch/axios to user URL — SSRF review on server.",
            ["javascript", "typescript"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "fetch($URL)"},
                {"pattern": "axios.get($URL)"},
                {"pattern": "axios($URL)"},
            ],
            metadata={"cwe": "CWE-918"},
        ),
        # mass assignment rails
        rule(
            "vibe-fw-rails-update-params",
            "[VIBE-SEC][framework] update(params) without strong params.",
            ["ruby"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "$M.update(params)"},
                {"pattern": "$M.update_attributes(params)"},
                {"pattern": "$M.assign_attributes(params)"},
            ],
            metadata={"cwe": "CWE-915", "framework": "rails", "kb_path": "languages/ruby/mass-assignment.md"},
        ),
        # jwt decode without verify
        rule(
            "vibe-fw-jwt-decode",
            "[VIBE-SEC][framework] jwt.decode without verify is not authentication.",
            ["javascript", "typescript", "python"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "jwt.decode(...)"},
                {"pattern": "jwt.decode($T, {complete: true})"},
            ],
            metadata={"cwe": "CWE-287"},
        ),
        # eval variants already — add setTimeout string
        rule(
            "vibe-fw-js-settimeout-string",
            "[VIBE-SEC][framework] setTimeout/setInterval with string is eval-like.",
            ["javascript", "typescript"],
            pattern_either=[
                {"pattern": "setTimeout($S, ...)"},
                {"pattern": "setInterval($S, ...)"},
            ],
            metadata={"cwe": "CWE-95"},
        ),
        # groovy/java ProcessBuilder
        rule(
            "vibe-fw-java-processbuilder",
            "[VIBE-SEC][framework] ProcessBuilder may execute OS commands.",
            ["java"],
            pattern="new ProcessBuilder(...)",
            metadata={"cwe": "CWE-78"},
        ),
        # Go exec
        rule(
            "vibe-fw-go-exec-command",
            "[VIBE-SEC][framework] exec.Command with user input.",
            ["go"],
            severity="WARNING",
            pattern="exec.Command(...)",
            metadata={"cwe": "CWE-78"},
        ),
        # Rust Command
        rule(
            "vibe-fw-rust-command",
            "[VIBE-SEC][framework] std::process::Command — review args.",
            ["rust"],
            severity="WARNING",
            pattern="Command::new(...)",
            metadata={"cwe": "CWE-78"},
        ),
        # SQLi f-string more
        rule(
            "vibe-fw-python-sqlalchemy-text",
            "[VIBE-SEC][framework] SQLAlchemy text() with f-string.",
            ["python"],
            pattern_either=[
                {"pattern": "text(f\"...\")"},
                {"pattern": "text(f'...')"},
            ],
            metadata={"cwe": "CWE-89", "framework": "sqlalchemy"},
        ),
        # Hardcoded password pattern
        rule(
            "vibe-fw-hardcoded-password-assign",
            "[VIBE-SEC][framework] Hardcoded password assignment smell.",
            ["python", "javascript", "typescript", "java", "go"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "password = \"...\""},
                {"pattern": "password = '...'"},
                {"pattern": "PASSWORD = \"...\""},
            ],
            metadata={"cwe": "CWE-798"},
        ),
    ]


EXCLUDE = {
    "paths": {
        "exclude": [
            "**/test/**",
            "**/tests/**",
            "**/node_modules/**",
            "**/.venv/**",
            "**/venv/**",
            "**/vendor/**",
            "**/*_test.py",
            "**/*_test.go",
            "**/__tests__/**",
        ]
    }
}


def with_paths(rules: list[dict]) -> list[dict]:
    out = []
    for r in rules:
        if "paths" not in r:
            r = {**r, "paths": EXCLUDE["paths"]}
        out.append(r)
    return out


def main() -> None:
    packs = {
        "vibe-python.yml": with_paths(python_rules()),
        "vibe-javascript.yml": with_paths(javascript_rules()),
        "vibe-java.yml": with_paths(java_rules()),
        "vibe-go.yml": with_paths(go_rules()),
        "vibe-csharp.yml": with_paths(csharp_rules()),
        "vibe-c.yml": with_paths(c_rules()),
        "vibe-php.yml": with_paths(php_rules()),
        "vibe-ruby.yml": with_paths(ruby_rules()),
        "vibe-rust.yml": with_paths(rust_rules()),
        "vibe-solidity.yml": with_paths(solidity_rules()),
        "vibe-typescript.yml": with_paths(typescript_rules()),
        "vibe-kotlin.yml": with_paths(kotlin_rules()),
        "vibe-swift.yml": with_paths(swift_rules()),
        "vibe-dangerous.yml": with_paths(dangerous_builtin()),
        "vibe-framework.yml": with_paths(framework_rules()),
    }
    total = 0
    by = {}
    ids = []
    for name, rules in packs.items():
        n = write_yaml(name, rules)
        total += n
        by[name] = n
        for r in rules:
            ids.append(r["id"])
        print(f"  {name}: {n}")
    dup = [i for i in ids if ids.count(i) > 1]
    if dup:
        print("DUP IDS", set(dup))
    meta = {
        "total_rules": total,
        "total_files": len(packs),
        "by_file": by,
        "unique_ids": len(set(ids)),
        "generator": "scripts/generate_quality_semgrep.py + expand_framework_semgrep.py",
        "paths_exclude": EXCLUDE["paths"]["exclude"],
    }
    (OUT / "metadata.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print("TOTAL", total, "unique", len(set(ids)))


if __name__ == "__main__":
    main()
