#!/usr/bin/env python3
"""
Generate high-quality Semgrep rules for vibe-coding dangerous patterns.
These are real API-level patterns (not literal KB snippet copies).
"""
from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "semgrep-rules"
OUT.mkdir(exist_ok=True)


def rule(
    rid: str,
    message: str,
    languages: list[str],
    severity: str = "ERROR",
    patterns: dict | None = None,
    pattern: str | None = None,
    pattern_either: list | None = None,
    pattern_regex: str | None = None,
    metadata: dict | None = None,
    paths: dict | None = None,
) -> dict:
    r: dict = {
        "id": rid,
        "message": message,
        "languages": languages,
        "severity": severity,
        "metadata": metadata
        or {
            "category": "security",
            "cwe": "CWE-670",
            "technology": languages,
            "references": ["https://owasp.org/"],
            "vibe-coding": True,
        },
    }
    if pattern is not None:
        r["pattern"] = pattern
    if pattern_either is not None:
        r["pattern-either"] = pattern_either
    if patterns is not None:
        r["patterns"] = patterns
    if pattern_regex is not None:
        r["pattern-regex"] = pattern_regex
    if paths is not None:
        r["paths"] = paths
    return r


def python_rules() -> list[dict]:
    return [
        rule(
            "vibe-python-eval",
            "[VIBE-SEC] eval() executes arbitrary code — never pass untrusted input. Prefer ast.literal_eval for data. KB: languages/python/eval-exec.md",
            ["python"],
            pattern="eval(...)",
            metadata={"cwe": "CWE-95", "kb_path": "languages/python/eval-exec.md"},
        ),
        rule(
            "vibe-python-exec",
            "[VIBE-SEC] exec() executes arbitrary code. KB: languages/python/eval-exec.md",
            ["python"],
            pattern="exec(...)",
            metadata={"cwe": "CWE-95", "kb_path": "languages/python/eval-exec.md"},
        ),
        rule(
            "vibe-python-pickle-loads",
            "[VIBE-SEC] pickle.loads/load can RCE on untrusted data. Use JSON or safer serializers. KB: languages/python/pickle-rce.md",
            ["python"],
            pattern_either=[
                {"pattern": "pickle.loads(...)"},
                {"pattern": "pickle.load(...)"},
                {"pattern": "cPickle.loads(...)"},
                {"pattern": "cPickle.load(...)"},
            ],
            metadata={"cwe": "CWE-502", "kb_path": "languages/python/pickle-rce.md"},
        ),
        rule(
            "vibe-python-yaml-load",
            "[VIBE-SEC] yaml.load without SafeLoader can execute arbitrary constructors. Use yaml.safe_load. KB: languages/python/insecure-deserialization-alt.md",
            ["python"],
            patterns=[
                {"pattern": "yaml.load(...)"},
                {
                    "pattern-not": "yaml.load(..., Loader=yaml.SafeLoader)",
                },
                {
                    "pattern-not": "yaml.load(..., Loader=yaml.CSafeLoader)",
                },
                {
                    "pattern-not": "yaml.safe_load(...)",
                },
            ],
            metadata={"cwe": "CWE-502", "kb_path": "languages/python/insecure-deserialization-alt.md"},
        ),
        rule(
            "vibe-python-shell-true",
            "[VIBE-SEC] subprocess with shell=True enables command injection. Pass argv list and shell=False. KB: languages/python/command-injection.md",
            ["python"],
            pattern_either=[
                {"pattern": "subprocess.$FUNC(..., shell=True, ...)"},
                {"pattern": "subprocess.$FUNC(..., shell=True)"},
                {"pattern": "os.system(...)"},
                {"pattern": "os.popen(...)"},
            ],
            metadata={"cwe": "CWE-78", "kb_path": "languages/python/command-injection.md"},
        ),
        rule(
            "vibe-python-sql-format",
            "[VIBE-SEC] String-formatted SQL is injection-prone. Use parameterized queries. KB: languages/python/sql-injection.md",
            ["python"],
            pattern_either=[
                {"pattern": "cursor.execute(f\"...\")"},
                {"pattern": "cursor.execute(f'...')"},
                {"pattern": "cursor.execute(... % ...)"},
                {"pattern": "cursor.execute(... .format(...))"},
                {"pattern": ".$METHOD(f\"SELECT ...\")"},
                {"pattern": ".$METHOD(f\"INSERT ...\")"},
                {"pattern": ".$METHOD(f\"UPDATE ...\")"},
                {"pattern": ".$METHOD(f\"DELETE ...\")"},
            ],
            metadata={"cwe": "CWE-89", "kb_path": "languages/python/sql-injection.md"},
        ),
        rule(
            "vibe-python-assert-security",
            "[VIBE-SEC] assert is stripped with -O; never use for auth/security checks.",
            ["python"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "assert $AUTH"},
                {"pattern": "assert $USER.is_admin"},
                {"pattern": "assert $USER.is_authenticated"},
            ],
            metadata={"cwe": "CWE-617"},
        ),
        rule(
            "vibe-python-debug-true",
            "[VIBE-SEC] DEBUG=True or Flask debug mode must not ship to production. KB: languages/python/flask-django-misconfig.md",
            ["python"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "DEBUG = True"},
                {"pattern": "app.run(..., debug=True, ...)"},
                {"pattern": "app.run(debug=True)"},
            ],
            metadata={"cwe": "CWE-489", "kb_path": "languages/python/flask-django-misconfig.md"},
        ),
        rule(
            "vibe-python-mark-safe",
            "[VIBE-SEC] mark_safe / Markup on user data can cause XSS/SSTI. KB: languages/python/template-injection.md",
            ["python"],
            pattern_either=[
                {"pattern": "mark_safe(...)"},
                {"pattern": "Markup(...)"},
            ],
            metadata={"cwe": "CWE-79", "kb_path": "languages/python/template-injection.md"},
        ),
        rule(
            "vibe-python-hashlib-md5-sha1",
            "[VIBE-SEC] MD5/SHA1 are weak for security-sensitive hashing. Use hashlib.sha256+ or password hashers. KB: languages/python/crypto-mistakes.md",
            ["python"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "hashlib.md5(...)"},
                {"pattern": "hashlib.sha1(...)"},
            ],
            metadata={"cwe": "CWE-328", "kb_path": "languages/python/crypto-mistakes.md"},
        ),
        rule(
            "vibe-python-random-for-secrets",
            "[VIBE-SEC] random module is not cryptographically secure. Use secrets module. KB: languages/python/crypto-mistakes.md",
            ["python"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "random.random()"},
                {"pattern": "random.randint(...)"},
                {"pattern": "random.choice(...)"},
                {"pattern": "random.randrange(...)"},
            ],
            metadata={"cwe": "CWE-338", "kb_path": "languages/python/crypto-mistakes.md"},
        ),
        rule(
            "vibe-python-requests-verify-false",
            "[VIBE-SEC] TLS verification disabled (verify=False) enables MITM. KB: languages/python/ssrf-python.md",
            ["python"],
            pattern_either=[
                {"pattern": "requests.$METHOD(..., verify=False, ...)"},
                {"pattern": "requests.$METHOD(..., verify=False)"},
            ],
            metadata={"cwe": "CWE-295", "kb_path": "languages/python/ssrf-python.md"},
        ),
    ]


def javascript_rules() -> list[dict]:
    return [
        rule(
            "vibe-js-eval",
            "[VIBE-SEC] eval() / new Function() execute arbitrary JS. KB: languages/javascript/eval-injection.md",
            ["javascript", "typescript"],
            pattern_either=[
                {"pattern": "eval(...)"},
                {"pattern": "new Function(...)"},
                {"pattern": "Function(...)"},
            ],
            metadata={"cwe": "CWE-95", "kb_path": "languages/javascript/eval-injection.md"},
        ),
        rule(
            "vibe-js-innerhtml",
            "[VIBE-SEC] Assigning to innerHTML/outerHTML with untrusted data is XSS. Use textContent or sanitize. KB: languages/javascript/react-security.md",
            ["javascript", "typescript"],
            pattern_either=[
                {"pattern": "$EL.innerHTML = ..."},
                {"pattern": "$EL.outerHTML = ..."},
                {"pattern": "document.write(...)"},
            ],
            metadata={"cwe": "CWE-79", "kb_path": "languages/javascript/react-security.md"},
        ),
        rule(
            "vibe-js-dangerously-set-innerhtml",
            "[VIBE-SEC] dangerouslySetInnerHTML is XSS-prone without strict sanitization. KB: languages/javascript/react-security.md",
            ["javascript", "typescript"],
            pattern="<... dangerouslySetInnerHTML=... />",
            metadata={"cwe": "CWE-79", "kb_path": "languages/javascript/react-security.md"},
        ),
        rule(
            "vibe-js-child-process-exec",
            "[VIBE-SEC] child_process exec/execSync with user input is command injection. Prefer execFile/spawn with args array. KB: languages/javascript/ssrf-node.md",
            ["javascript", "typescript"],
            pattern_either=[
                {"pattern": "child_process.exec(...)"},
                {"pattern": "child_process.execSync(...)"},
                {"pattern": "exec(...)"},
                {"pattern": "execSync(...)"},
            ],
            metadata={"cwe": "CWE-78"},
        ),
        rule(
            "vibe-js-prototype-pollution-merge",
            "[VIBE-SEC] Recursive merge / __proto__ assignment can prototype-pollute. KB: languages/javascript/prototype-pollution.md",
            ["javascript", "typescript"],
            pattern_either=[
                {"pattern": "$O['__proto__'] = ..."},
                {"pattern": "$O.__proto__ = ..."},
                {"pattern": "$O['constructor']['prototype'] = ..."},
            ],
            metadata={"cwe": "CWE-1321", "kb_path": "languages/javascript/prototype-pollution.md"},
        ),
        rule(
            "vibe-js-jwt-none",
            "[VIBE-SEC] JWT algorithm confusion / none alg risks. Never accept alg from token header unchecked. KB: languages/javascript/jwt-misuse.md",
            ["javascript", "typescript"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "jwt.verify($T, $S, {algorithms: ['none'], ...})"},
                {"pattern": "jwt.decode($T, {complete: true})"},
            ],
            metadata={"cwe": "CWE-347", "kb_path": "languages/javascript/jwt-misuse.md"},
        ),
        rule(
            "vibe-js-disable-tls",
            "[VIBE-SEC] NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS validation.",
            ["javascript", "typescript"],
            pattern_either=[
                {"pattern": "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'"},
                {"pattern": "process.env.NODE_TLS_REJECT_UNAUTHORIZED = \"0\""},
            ],
            metadata={"cwe": "CWE-295"},
        ),
        rule(
            "vibe-js-sql-concat",
            "[VIBE-SEC] String-concatenated SQL is injection-prone. Use parameterized queries. KB: languages/javascript/express-security.md",
            ["javascript", "typescript"],
            pattern_either=[
                {"pattern": "$DB.query(`...${...}...`)"},
                {"pattern": "$DB.execute(`...${...}...`)"},
                {"pattern": "$DB.query('...' + ...)"},
                {"pattern": "$DB.query(\"...\" + ...)"},
            ],
            metadata={"cwe": "CWE-89", "kb_path": "languages/javascript/express-security.md"},
        ),
        rule(
            "vibe-js-cors-star-credentials",
            "[VIBE-SEC] CORS origin '*' with credentials is invalid/dangerous. KB: common/cors-deep.md",
            ["javascript", "typescript"],
            severity="WARNING",
            pattern_either=[
                {
                    "pattern": "cors({origin: '*', credentials: true, ...})"
                },
                {
                    "pattern": "cors({origin: \"*\", credentials: true, ...})"
                },
            ],
            metadata={"cwe": "CWE-942", "kb_path": "common/cors-deep.md"},
        ),
        rule(
            "vibe-js-postmessage-star",
            "[VIBE-SEC] postMessage with targetOrigin '*' leaks data cross-origin. KB: languages/javascript/service-worker-attacks.md",
            ["javascript", "typescript"],
            pattern_either=[
                {"pattern": "$W.postMessage(..., '*')"},
                {"pattern": "$W.postMessage(..., \"*\")"},
            ],
            metadata={"cwe": "CWE-345"},
        ),
    ]


def java_rules() -> list[dict]:
    return [
        rule(
            "vibe-java-objectinputstream",
            "[VIBE-SEC] Java deserialization via ObjectInputStream can RCE. Avoid on untrusted data. KB: languages/java/deserialization-rce.md",
            ["java"],
            pattern_either=[
                {"pattern": "new ObjectInputStream(...)"},
                {"pattern": "(ObjectInputStream $O).readObject()"},
            ],
            metadata={"cwe": "CWE-502", "kb_path": "languages/java/deserialization-rce.md"},
        ),
        rule(
            "vibe-java-runtime-exec",
            "[VIBE-SEC] Runtime.exec / ProcessBuilder with user input is command injection. KB: languages/java/expression-injection.md",
            ["java"],
            pattern_either=[
                {"pattern": "Runtime.getRuntime().exec(...)"},
                {"pattern": "(new ProcessBuilder(...)).start()"},
            ],
            metadata={"cwe": "CWE-78"},
        ),
        rule(
            "vibe-java-sql-concat",
            "[VIBE-SEC] SQL string concatenation enables injection. Use PreparedStatement. KB: languages/java/sql-injection.md",
            ["java"],
            pattern_either=[
                {"pattern": "$C.createStatement().executeQuery(\"...\" + ...)"},
                {"pattern": "$C.prepareStatement(\"...\" + ...)"},
                {"pattern": "$C.createStatement().executeUpdate(\"...\" + ...)"},
            ],
            metadata={"cwe": "CWE-89", "kb_path": "languages/java/sql-injection.md"},
        ),
        rule(
            "vibe-java-xxe-documentbuilder",
            "[VIBE-SEC] XML parsers without XXE hardening are dangerous. Disable external entities. KB: languages/java/xxe.md",
            ["java"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "DocumentBuilderFactory.newInstance()"},
                {"pattern": "SAXParserFactory.newInstance()"},
                {"pattern": "XMLInputFactory.newInstance()"},
            ],
            metadata={"cwe": "CWE-611", "kb_path": "languages/java/xxe.md"},
        ),
        rule(
            "vibe-java-scriptengine-eval",
            "[VIBE-SEC] ScriptEngine.eval executes arbitrary script. KB: languages/java/nashorn-scriptengine.md",
            ["java"],
            pattern="$E.eval(...)",
            metadata={"cwe": "CWE-94", "kb_path": "languages/java/nashorn-scriptengine.md"},
        ),
    ]


def go_rules() -> list[dict]:
    return [
        rule(
            "vibe-go-sql-sprintf",
            "[VIBE-SEC] fmt.Sprintf into SQL is injection-prone. Use database/sql placeholders. KB: languages/go/sql-injection.md",
            ["go"],
            pattern_either=[
                {"pattern": "$DB.Query(fmt.Sprintf(...))"},
                {"pattern": "$DB.Exec(fmt.Sprintf(...))"},
                {"pattern": "$DB.QueryRow(fmt.Sprintf(...))"},
            ],
            metadata={"cwe": "CWE-89", "kb_path": "languages/go/sql-injection.md"},
        ),
        rule(
            "vibe-go-text-template",
            "[VIBE-SEC] text/template does not auto-escape HTML — XSS risk in web contexts. Prefer html/template. KB: languages/go/template-injection.md",
            ["go"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "template.New(...)"},
                {"pattern": "template.Must(...)"},
            ],
            metadata={"cwe": "CWE-79", "kb_path": "languages/go/template-injection.md"},
        ),
        rule(
            "vibe-go-tls-insecure",
            "[VIBE-SEC] InsecureSkipVerify disables TLS verification. KB: languages/go/http-security-deep.md",
            ["go"],
            pattern="tls.Config{..., InsecureSkipVerify: true, ...}",
            metadata={"cwe": "CWE-295", "kb_path": "languages/go/http-security-deep.md"},
        ),
        rule(
            "vibe-go-math-rand",
            "[VIBE-SEC] math/rand is not crypto-safe for tokens/secrets. Use crypto/rand. KB: languages/go/crypto-mistakes.md",
            ["go"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "rand.Intn(...)"},
                {"pattern": "rand.Read(...)"},
            ],
            metadata={"cwe": "CWE-338", "kb_path": "languages/go/crypto-mistakes.md"},
        ),
        rule(
            "vibe-go-http-serve",
            "[VIBE-SEC] http.ListenAndServe without timeouts risks slowloris. Set ReadHeaderTimeout etc. KB: languages/go/http-security-deep.md",
            ["go"],
            severity="WARNING",
            pattern="http.ListenAndServe(...)",
            metadata={"cwe": "CWE-400", "kb_path": "languages/go/http-security-deep.md"},
        ),
    ]


def csharp_rules() -> list[dict]:
    return [
        rule(
            "vibe-csharp-binaryformatter",
            "[VIBE-SEC] BinaryFormatter is obsolete and RCE-prone. Use safe serializers. KB: languages/csharp/deserialization.md",
            ["csharp"],
            pattern_either=[
                {"pattern": "new BinaryFormatter()"},
                {"pattern": "(new BinaryFormatter()).Deserialize(...)"},
            ],
            metadata={"cwe": "CWE-502", "kb_path": "languages/csharp/deserialization.md"},
        ),
        rule(
            "vibe-csharp-sql-concat",
            "[VIBE-SEC] Concatenated SQL strings enable injection. Use parameters. KB: languages/csharp/sql-injection-ef.md",
            ["csharp"],
            pattern_either=[
                {"pattern": "new SqlCommand(... + ..., ...)"},
                {"pattern": "$CMD.CommandText = ... + ..."},
                {"pattern": "FromSqlRaw($S + ...)"},
                {"pattern": "ExecuteSqlRaw($S + ...)"},
            ],
            metadata={"cwe": "CWE-89", "kb_path": "languages/csharp/sql-injection-ef.md"},
        ),
        rule(
            "vibe-csharp-xxe",
            "[VIBE-SEC] XmlDocument/XmlTextReader may resolve external entities. Harden DTD settings. KB: languages/csharp/xxe-attacks.md",
            ["csharp"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "new XmlDocument()"},
                {"pattern": "new XmlTextReader(...)"},
            ],
            metadata={"cwe": "CWE-611", "kb_path": "languages/csharp/xxe-attacks.md"},
        ),
        rule(
            "vibe-csharp-viewstate-mac-false",
            "[VIBE-SEC] enableViewStateMac=false weakens ASP.NET integrity protections.",
            ["csharp"],
            severity="WARNING",
            pattern_regex=r"enableViewStateMac\s*=\s*\"?false\"?",
            metadata={"cwe": "CWE-345"},
        ),
    ]


def c_rules() -> list[dict]:
    return [
        rule(
            "vibe-c-gets",
            "[VIBE-SEC] gets() is never safe (unbounded buffer). Use fgets. KB: languages/c-cpp/unsafe-functions.md",
            ["c", "cpp"],
            pattern="gets(...)",
            metadata={"cwe": "CWE-242", "kb_path": "languages/c-cpp/unsafe-functions.md"},
        ),
        rule(
            "vibe-c-strcpy",
            "[VIBE-SEC] strcpy/strcat are unbounded. Prefer strncpy/strlcpy with explicit bounds. KB: languages/c-cpp/buffer-overflow.md",
            ["c", "cpp"],
            pattern_either=[
                {"pattern": "strcpy(...)"},
                {"pattern": "strcat(...)"},
                {"pattern": "sprintf(...)"},
                {"pattern": "vsprintf(...)"},
            ],
            metadata={"cwe": "CWE-120", "kb_path": "languages/c-cpp/buffer-overflow.md"},
        ),
        rule(
            "vibe-c-format-string",
            "[VIBE-SEC] printf(user_controlled) is a format-string bug. Use printf(\"%s\", buf). KB: languages/c-cpp/format-string.md",
            ["c", "cpp"],
            pattern_either=[
                {"pattern": "printf($VAR)"},
                {"pattern": "fprintf($F, $VAR)"},
                {"pattern": "sprintf($B, $VAR)"},
            ],
            metadata={"cwe": "CWE-134", "kb_path": "languages/c-cpp/format-string.md"},
        ),
        rule(
            "vibe-c-system",
            "[VIBE-SEC] system() with untrusted input is command injection. KB: languages/c-cpp/unsafe-functions.md",
            ["c", "cpp"],
            pattern="system(...)",
            metadata={"cwe": "CWE-78", "kb_path": "languages/c-cpp/unsafe-functions.md"},
        ),
        rule(
            "vibe-c-scanf",
            "[VIBE-SEC] scanf %s without width is buffer overflow. KB: languages/c-cpp/buffer-overflow.md",
            ["c", "cpp"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "scanf(\"%s\", ...)"},
                {"pattern": "scanf(\"%s\", $V)"},
            ],
            metadata={"cwe": "CWE-120", "kb_path": "languages/c-cpp/buffer-overflow.md"},
        ),
    ]


def php_rules() -> list[dict]:
    return [
        rule(
            "vibe-php-unserialize",
            "[VIBE-SEC] unserialize on untrusted data can RCE via object injection. Prefer json_decode. KB: languages/php/unserialize-rce.md",
            ["php"],
            pattern="unserialize(...)",
            metadata={"cwe": "CWE-502", "kb_path": "languages/php/unserialize-rce.md"},
        ),
        rule(
            "vibe-php-eval",
            "[VIBE-SEC] eval() executes arbitrary PHP. KB: languages/php/command-injection.md",
            ["php"],
            pattern="eval(...)",
            metadata={"cwe": "CWE-95"},
        ),
        rule(
            "vibe-php-command",
            "[VIBE-SEC] system/exec/shell_exec/passthru with user input is RCE. KB: languages/php/command-injection.md",
            ["php"],
            pattern_either=[
                {"pattern": "system(...)"},
                {"pattern": "exec(...)"},
                {"pattern": "shell_exec(...)"},
                {"pattern": "passthru(...)"},
                {"pattern": "popen(...)"},
            ],
            metadata={"cwe": "CWE-78", "kb_path": "languages/php/command-injection.md"},
        ),
        rule(
            "vibe-php-include-user",
            "[VIBE-SEC] Dynamic include/require enables LFI/RFI. Use allowlists. KB: languages/php/lfi-rfi.md",
            ["php"],
            pattern_either=[
                {"pattern": "include($VAR)"},
                {"pattern": "include_once($VAR)"},
                {"pattern": "require($VAR)"},
                {"pattern": "require_once($VAR)"},
            ],
            metadata={"cwe": "CWE-98", "kb_path": "languages/php/lfi-rfi.md"},
        ),
        rule(
            "vibe-php-loose-compare",
            "[VIBE-SEC] Loose comparison (==) enables type juggling auth bypass. Use ===. KB: languages/php/type-juggling.md",
            ["php"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "$PASSWORD == $HASH"},
                {"pattern": "$HASH == $PASSWORD"},
                {"pattern": "$TOKEN == $EXPECTED"},
            ],
            metadata={"cwe": "CWE-697", "kb_path": "languages/php/type-juggling.md"},
        ),
        rule(
            "vibe-php-md5-password",
            "[VIBE-SEC] md5/sha1 for passwords is broken. Use password_hash. KB: languages/php/session-security.md",
            ["php"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "md5($PASSWORD)"},
                {"pattern": "sha1($PASSWORD)"},
            ],
            metadata={"cwe": "CWE-328"},
        ),
    ]


def ruby_rules() -> list[dict]:
    return [
        rule(
            "vibe-ruby-yaml-load",
            "[VIBE-SEC] YAML.load can deserialize arbitrary objects (RCE). Use YAML.safe_load. KB: languages/ruby/yaml-deserialization.md",
            ["ruby"],
            pattern_either=[
                {"pattern": "YAML.load(...)"},
                {"pattern": "Psych.load(...)"},
            ],
            metadata={"cwe": "CWE-502", "kb_path": "languages/ruby/yaml-deserialization.md"},
        ),
        rule(
            "vibe-ruby-eval",
            "[VIBE-SEC] eval/instance_eval/class_eval execute code. KB: languages/ruby/command-injection.md",
            ["ruby"],
            pattern_either=[
                {"pattern": "eval(...)"},
                {"pattern": "instance_eval(...)"},
                {"pattern": "class_eval(...)"},
            ],
            metadata={"cwe": "CWE-95"},
        ),
        rule(
            "vibe-ruby-system",
            "[VIBE-SEC] system/exec/` ` with interpolation is command injection. KB: languages/ruby/command-injection.md",
            ["ruby"],
            pattern_either=[
                {"pattern": "system(...)"},
                {"pattern": "exec(...)"},
                {"pattern": "Open3.capture2(...)"},
            ],
            metadata={"cwe": "CWE-78", "kb_path": "languages/ruby/command-injection.md"},
        ),
        rule(
            "vibe-ruby-sql-interpolation",
            "[VIBE-SEC] SQL string interpolation bypasses ActiveRecord safety. KB: languages/ruby/sql-injection.md",
            ["ruby"],
            pattern_either=[
                {"pattern": "where(\"...#{...}...\")"},
                {"pattern": "find_by_sql(\"...#{...}...\")"},
                {"pattern": "where('...' + ...)"},
            ],
            metadata={"cwe": "CWE-89", "kb_path": "languages/ruby/sql-injection.md"},
        ),
    ]


def rust_rules() -> list[dict]:
    return [
        rule(
            "vibe-rust-unsafe",
            "[VIBE-SEC] unsafe blocks bypass borrow checker — audit carefully. KB: languages/rust/",
            ["rust"],
            severity="WARNING",
            pattern="unsafe { ... }",
            metadata={"cwe": "CWE-119"},
        ),
        rule(
            "vibe-rust-transmute",
            "[VIBE-SEC] mem::transmute is extremely dangerous type punning.",
            ["rust"],
            pattern_either=[
                {"pattern": "std::mem::transmute(...)"},
                {"pattern": "mem::transmute(...)"},
            ],
            metadata={"cwe": "CWE-843"},
        ),
        rule(
            "vibe-rust-from-raw-parts",
            "[VIBE-SEC] slice::from_raw_parts requires upheld safety invariants.",
            ["rust"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "std::slice::from_raw_parts(...)"},
                {"pattern": "slice::from_raw_parts(...)"},
            ],
            metadata={"cwe": "CWE-119"},
        ),
    ]


def solidity_rules() -> list[dict]:
    return [
        rule(
            "vibe-sol-tx-origin",
            "[VIBE-SEC] tx.origin for auth is phishing-prone; use msg.sender. KB: languages/solidity/tx-origin.md",
            ["solidity"],
            pattern="tx.origin",
            metadata={"cwe": "CWE-346", "kb_path": "languages/solidity/tx-origin.md"},
        ),
        rule(
            "vibe-sol-delegatecall",
            "[VIBE-SEC] delegatecall to untrusted address risks storage takeover. KB: languages/solidity/",
            ["solidity"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "delegatecall(...)"},
                {"pattern": ".$X.delegatecall(...)"},
            ],
            metadata={"cwe": "CWE-829"},
        ),
        rule(
            "vibe-sol-selfdestruct",
            "[VIBE-SEC] selfdestruct/suicide can brick contracts or force-send ETH.",
            ["solidity"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "selfdestruct(...)"},
                {"pattern": "suicide(...)"},
            ],
            metadata={"cwe": "CWE-284"},
        ),
        rule(
            "vibe-sol-block-timestamp",
            "[VIBE-SEC] block.timestamp/blockhash are miner-influenced; not secure randomness. KB: languages/solidity/",
            ["solidity"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "block.timestamp"},
                {"pattern": "block.number"},
                {"pattern": "blockhash(...)"},
            ],
            metadata={"cwe": "CWE-330"},
        ),
    ]


def typescript_rules() -> list[dict]:
    return [
        rule(
            "vibe-ts-as-any",
            "[VIBE-SEC] `as any` disables type safety — often hides auth/input bugs. KB: languages/typescript/type-safety-bypass.md",
            ["typescript"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "$X as any"},
                {"pattern": "<any>$X"},
            ],
            metadata={"cwe": "CWE-704", "kb_path": "languages/typescript/type-safety-bypass.md"},
        ),
        rule(
            "vibe-ts-ts-ignore",
            "[VIBE-SEC] @ts-ignore / @ts-nocheck suppress real type errors. KB: languages/typescript/type-safety-bypass.md",
            ["typescript"],
            severity="WARNING",
            pattern_regex=r"@ts-ignore|@ts-nocheck",
            metadata={"cwe": "CWE-670", "kb_path": "languages/typescript/type-safety-bypass.md"},
        ),
        rule(
            "vibe-ts-eval-like",
            "[VIBE-SEC] eval/new Function in TS still executes at runtime. KB: languages/javascript/eval-injection.md",
            ["typescript"],
            pattern_either=[
                {"pattern": "eval(...)"},
                {"pattern": "new Function(...)"},
            ],
            metadata={"cwe": "CWE-95"},
        ),
    ]


def kotlin_rules() -> list[dict]:
    return [
        rule(
            "vibe-kotlin-not-null-assert",
            "[VIBE-SEC] !! null assertion crashes or hides null bugs. KB: languages/kotlin/null-safety-bypass.md",
            ["kotlin"],
            severity="WARNING",
            pattern="$X!!",
            metadata={"cwe": "CWE-476", "kb_path": "languages/kotlin/null-safety-bypass.md"},
        ),
        rule(
            "vibe-kotlin-runtime-exec",
            "[VIBE-SEC] Runtime.exec with user input is command injection.",
            ["kotlin"],
            pattern="Runtime.getRuntime().exec(...)",
            metadata={"cwe": "CWE-78"},
        ),
    ]


def swift_rules() -> list[dict]:
    return [
        rule(
            "vibe-swift-userdefaults-secret",
            "[VIBE-SEC] UserDefaults is not secure storage for secrets — use Keychain. KB: languages/swift/keychain-storage.md",
            ["swift"],
            severity="WARNING",
            pattern_either=[
                {"pattern": "UserDefaults.standard.set($SECRET, forKey: ...)"},
                {"pattern": "UserDefaults.standard.string(forKey: ...)"},
            ],
            metadata={"cwe": "CWE-312", "kb_path": "languages/swift/keychain-storage.md"},
        ),
        rule(
            "vibe-swift-http-ats",
            "[VIBE-SEC] NSAllowsArbitraryLoads disables ATS (MITM risk). KB: languages/swift/ios-security-deep.md",
            ["swift"],
            severity="WARNING",
            pattern_regex=r"NSAllowsArbitraryLoads",
            metadata={"cwe": "CWE-319", "kb_path": "languages/swift/ios-security-deep.md"},
        ),
    ]


def dangerous_builtin() -> list[dict]:
    """Cross-cutting dangerous API set (multi-language file)."""
    return (
        [
            rule(
                "vibe-dangerous-eval-python",
                "[VIBE-SEC][builtin] eval/exec",
                ["python"],
                pattern_either=[{"pattern": "eval(...)"}, {"pattern": "exec(...)"}],
                metadata={"cwe": "CWE-95", "builtin": True},
            ),
            rule(
                "vibe-dangerous-eval-js",
                "[VIBE-SEC][builtin] eval/Function",
                ["javascript", "typescript"],
                pattern_either=[
                    {"pattern": "eval(...)"},
                    {"pattern": "new Function(...)"},
                ],
                metadata={"cwe": "CWE-95", "builtin": True},
            ),
            rule(
                "vibe-dangerous-pickle",
                "[VIBE-SEC][builtin] pickle load",
                ["python"],
                pattern_either=[
                    {"pattern": "pickle.loads(...)"},
                    {"pattern": "pickle.load(...)"},
                ],
                metadata={"cwe": "CWE-502", "builtin": True},
            ),
            rule(
                "vibe-dangerous-gets",
                "[VIBE-SEC][builtin] gets",
                ["c", "cpp"],
                pattern="gets(...)",
                metadata={"cwe": "CWE-242", "builtin": True},
            ),
            rule(
                "vibe-dangerous-strcpy",
                "[VIBE-SEC][builtin] strcpy/sprintf",
                ["c", "cpp"],
                pattern_either=[
                    {"pattern": "strcpy(...)"},
                    {"pattern": "sprintf(...)"},
                ],
                metadata={"cwe": "CWE-120", "builtin": True},
            ),
            rule(
                "vibe-dangerous-system-c",
                "[VIBE-SEC][builtin] system()",
                ["c", "cpp"],
                pattern="system(...)",
                metadata={"cwe": "CWE-78", "builtin": True},
            ),
            rule(
                "vibe-dangerous-unserialize",
                "[VIBE-SEC][builtin] unserialize",
                ["php"],
                pattern="unserialize(...)",
                metadata={"cwe": "CWE-502", "builtin": True},
            ),
            rule(
                "vibe-dangerous-yaml-load",
                "[VIBE-SEC][builtin] YAML.load",
                ["ruby"],
                pattern="YAML.load(...)",
                metadata={"cwe": "CWE-502", "builtin": True},
            ),
            rule(
                "vibe-dangerous-binaryformatter",
                "[VIBE-SEC][builtin] BinaryFormatter",
                ["csharp"],
                pattern="new BinaryFormatter()",
                metadata={"cwe": "CWE-502", "builtin": True},
            ),
            rule(
                "vibe-dangerous-objectinputstream",
                "[VIBE-SEC][builtin] ObjectInputStream",
                ["java"],
                pattern="new ObjectInputStream(...)",
                metadata={"cwe": "CWE-502", "builtin": True},
            ),
            rule(
                "vibe-dangerous-tx-origin",
                "[VIBE-SEC][builtin] tx.origin",
                ["solidity"],
                pattern="tx.origin",
                metadata={"cwe": "CWE-346", "builtin": True},
            ),
            rule(
                "vibe-dangerous-child-process",
                "[VIBE-SEC][builtin] child_process.exec",
                ["javascript", "typescript"],
                pattern_either=[
                    {"pattern": "child_process.exec(...)"},
                    {"pattern": "child_process.execSync(...)"},
                ],
                metadata={"cwe": "CWE-78", "builtin": True},
            ),
            rule(
                "vibe-dangerous-shell-true",
                "[VIBE-SEC][builtin] shell=True",
                ["python"],
                pattern="subprocess.$F(..., shell=True, ...)",
                metadata={"cwe": "CWE-78", "builtin": True},
            ),
            rule(
                "vibe-dangerous-os-system",
                "[VIBE-SEC][builtin] os.system",
                ["python"],
                pattern="os.system(...)",
                metadata={"cwe": "CWE-78", "builtin": True},
            ),
        ]
    )


def write_yaml(name: str, rules: list[dict]) -> int:
    # Minimal YAML dumper without pyyaml dependency quirks
    def dump_value(v, indent=0):
        sp = "  " * indent
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return str(v)
        if isinstance(v, str):
            if "\n" in v or v.startswith("[") or ":" in v or v.startswith("#"):
                # block or quoted
                if "\n" in v:
                    lines = "\n".join(sp + "  " + line if line else sp + "  " for line in v.split("\n"))
                    return "|\n" + lines
                return json.dumps(v, ensure_ascii=False)
            if v == "" or any(c in v for c in " {}[]&*?|>!%@`"):
                return json.dumps(v, ensure_ascii=False)
            return v
        if isinstance(v, list):
            if not v:
                return "[]"
            # list of scalars?
            if all(isinstance(x, (str, int, float, bool)) for x in v):
                return "[" + ", ".join(dump_value(x) for x in v) + "]"
            parts = []
            for item in v:
                if isinstance(item, dict):
                    # inline single-key pattern dicts
                    if len(item) == 1:
                        k2, v2 = next(iter(item.items()))
                        parts.append(f"{sp}- {k2}: {dump_value(v2, indent+1)}")
                    else:
                        parts.append(f"{sp}-")
                        for k2, v2 in item.items():
                            if isinstance(v2, (dict, list)) and not (
                                isinstance(v2, list) and all(isinstance(x, (str, int, float, bool)) for x in v2)
                            ):
                                parts.append(f"{sp}  {k2}:")
                                dumped = dump_value(v2, indent + 2)
                                if dumped.startswith("\n") or "\n" in dumped:
                                    parts.append(dumped if dumped.startswith(sp) else dump_block(v2, indent + 2))
                                else:
                                    parts.append(f"{sp}    {dumped}")
                            else:
                                parts.append(f"{sp}  {k2}: {dump_value(v2, indent+2)}")
                else:
                    parts.append(f"{sp}- {dump_value(item, indent+1)}")
            return "\n".join(parts)
        if isinstance(v, dict):
            parts = []
            for k, val in v.items():
                if isinstance(val, list) and val and isinstance(val[0], dict):
                    parts.append(f"{sp}{k}:")
                    parts.append(dump_value(val, indent + 1))
                elif isinstance(val, dict):
                    parts.append(f"{sp}{k}:")
                    parts.append(dump_value(val, indent + 1))
                elif isinstance(val, list) and not all(isinstance(x, (str, int, float, bool)) for x in val):
                    parts.append(f"{sp}{k}:")
                    parts.append(dump_value(val, indent + 1))
                else:
                    parts.append(f"{sp}{k}: {dump_value(val, indent+1)}")
            return "\n".join(parts)
        return json.dumps(str(v))

    def dump_block(v, indent):
        return dump_value(v, indent)

    lines = ["rules:"]
    for r in rules:
        lines.append(f"- id: {r['id']}")
        for key in ("message", "severity", "languages", "pattern", "pattern-either", "patterns", "pattern-regex", "metadata", "paths"):
            if key not in r:
                continue
            val = r[key]
            if key in ("pattern-either", "patterns") and isinstance(val, list):
                lines.append(f"  {key}:")
                for item in val:
                    if isinstance(item, dict) and len(item) == 1:
                        k2, v2 = next(iter(item.items()))
                        # multi-line pattern?
                        if isinstance(v2, str) and "\n" in v2:
                            lines.append(f"  - {k2}: |")
                            for ln in v2.split("\n"):
                                lines.append(f"      {ln}")
                        else:
                            dumped = dump_value(v2)
                            lines.append(f"  - {k2}: {dumped}")
                    else:
                        lines.append("  -")
                        for k2, v2 in item.items():
                            lines.append(f"      {k2}: {dump_value(v2)}")
            elif key == "metadata" and isinstance(val, dict):
                lines.append("  metadata:")
                for k2, v2 in val.items():
                    lines.append(f"    {k2}: {dump_value(v2)}")
            elif key == "languages" and isinstance(val, list):
                lines.append(f"  languages: [{', '.join(val)}]")
            elif key == "pattern" and isinstance(val, str) and "\n" in val:
                lines.append("  pattern: |")
                for ln in val.split("\n"):
                    lines.append(f"    {ln}")
            else:
                lines.append(f"  {key}: {dump_value(val)}")
        lines.append("")

    path = OUT / name
    path.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    return len(rules)


def main() -> None:
    packs = {
        "vibe-python.yml": python_rules(),
        "vibe-javascript.yml": javascript_rules(),
        "vibe-java.yml": java_rules(),
        "vibe-go.yml": go_rules(),
        "vibe-csharp.yml": csharp_rules(),
        "vibe-c.yml": c_rules(),
        "vibe-php.yml": php_rules(),
        "vibe-ruby.yml": ruby_rules(),
        "vibe-rust.yml": rust_rules(),
        "vibe-solidity.yml": solidity_rules(),
        "vibe-typescript.yml": typescript_rules(),
        "vibe-kotlin.yml": kotlin_rules(),
        "vibe-swift.yml": swift_rules(),
        "vibe-dangerous.yml": dangerous_builtin(),
    }
    total = 0
    by_lang = {}
    for name, rules in packs.items():
        n = write_yaml(name, rules)
        total += n
        by_lang[name] = n
        print(f"  {name}: {n}")

    meta = {
        "total_rules": total,
        "total_files": len(packs),
        "by_file": by_lang,
        "generator": "scripts/generate_quality_semgrep.py",
        "note": "API-level patterns for vibe-coding dangerous sinks; not literal KB snippet copies.",
        "output_dir": str(OUT),
    }
    (OUT / "metadata.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print(f"TOTAL {total} rules")


if __name__ == "__main__":
    main()
