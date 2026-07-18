#!/usr/bin/env python
"""
KB → Semgrep Rule Converter
Reads all vulnerability .md files, extracts vulnerable code patterns,
converts them to Semgrep YAML rules.
"""
import os
import re
import yaml
import json
from pathlib import Path

BASE = r'C:\Users\muham\security-knowledge-bank'
OUTPUT = os.path.join(BASE, 'semgrep-rules')

# Language mapping for Semgrep
LANG_MAP = {
    'python': 'python',
    'javascript': 'javascript',
    'typescript': 'typescript',
    'java': 'java',
    'go': 'go',
    'rust': 'rust',
    'csharp': 'csharp',
    'c-cpp': 'c',  # will be checked for cpp patterns
    'php': 'php',
    'ruby': 'ruby',
    'swift': 'swift',
    'kotlin': 'kotlin',
    'solidity': 'solidity',
}

# Dangerous functions by language (for fallback pattern detection)
DANGEROUS_FUNCS = {
    'python': ['eval\(', 'exec\(', 'pickle.load', 'os.system', 'subprocess.*shell=True', 'yaml.load('],
    'javascript': ['eval\(', 'innerHTML', 'dangerouslySetInnerHTML', 'prototype', 'Function\('],
    'java': ['ObjectInputStream', 'readObject', 'Runtime.exec', 'ProcessBuilder'],
    'go': ['sql\.Open', 'fmt\.Sprintf.*WHERE', 'text/template'],
    'rust': ['unsafe\s*\{', 'transmute', 'MaybeUninit'],
    'csharp': ['BinaryFormatter', 'Deserialize', 'SqlCommand\(.*\+'],
    'c': ['gets\(', 'strcpy\(', 'sprintf\(', 'printf\(', 'system\('],
    'php': ['unserialize\(', 'eval\(', 'system\(', 'shell_exec'],
    'ruby': ['YAML\.load\(', 'eval\(', 'send\(', 'system\('],
    'swift': ['UserDefaults', 'force_unwrap'],
    'kotlin': ['!!', 'SharedPreferences'],
    'solidity': ['tx\.origin', 'call\.value', 'transfer\('],
}

# Severity mapping
SEV_MAP = {
    '🔴 Kritik': 'ERROR',
    '🔴': 'ERROR',
    '🟠 Yüksek': 'WARNING',
    '🟠': 'WARNING',
    '🟡 Orta': 'INFO',
    '🟡': 'INFO',
}

def extract_semgrep_pattern(code_text, language):
    """Convert vulnerable code to Semgrep pattern with proper ellipsis handling."""
    if not code_text:
        return None
    
    lines = code_text.split('\n')
    cleaned = []
    
    for line in lines:
        stripped = line.strip()
        
        # Skip comment lines
        if not stripped or stripped.startswith('#') or stripped.startswith('//'):
            continue
        
        # Preserve actual function calls and control flow
        # Only replace literal string values with ellipsis
        line_out = line
        
        # Replace string literals with ...
        line_out = re.sub(r"'(?:[^'\\]|\\.)*'", '...', line_out)
        line_out = re.sub(r'"(?:[^"\\]|\\.)*"', '...', line_out)
        
        # Replace numeric literals with ...
        line_out = re.sub(r'\b\d+\b', '...', line_out)
        
        # Normalize multiple ... into single ... (exactly 3 dots)
        line_out = re.sub(r'\.\s*\.\s*\.(\s*\.\s*\.\s*\.)+', '...', line_out)
        line_out = re.sub(r'\.{4,}', '...', line_out)
        
        # Keep variable names intact (they're important for matching)
        cleaned.append(line_out)
    
    if not cleaned:
        return None
    
    # Take the first 1-3 lines that have meaningful content
    meaningful = [l for l in cleaned if re.search(r'[a-zA-Z]{3,}', l)]
    if not meaningful:
        return None
    
    # Use at most 5 lines
    pattern_lines = cleaned[:5]
    pattern = '\n'.join(pattern_lines)

    return pattern

def detect_severity(content):
    """Detect severity from file content."""
    for kw, sev in SEV_MAP.items():
        if kw in content[:2000]:
            return sev
    # Check text patterns
    sev_patterns = [
        (r'Severity:\s*🔴', 'ERROR'),
        (r'Severity:\s*🟠', 'WARNING'),
        (r'Severity:\s*🟡', 'INFO'),
        (r'CVSS\s*(10|9\.)', 'ERROR'),
        (r'CVSS\s*(8\.|7\.)', 'WARNING'),
        (r'CVSS\s*(6\.|5\.|4\.)', 'INFO'),
    ]
    for pat, sev in sev_patterns:
        if re.search(pat, content[:2000]):
            return sev
    return 'WARNING'

def extract_cwe(content):
    """Extract CWE ID from content."""
    match = re.search(r'CWE-(\d+)', content)
    if match:
        return f"CWE-{match.group(1)}"
    return None

def extract_title(filepath):
    """Extract title from file."""
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        first_line = f.readline().strip()
    title = first_line.lstrip('#').strip()
    return title

def find_case_study(vuln_name, language):
    """Find related case study file."""
    base_dir = os.path.join(BASE, 'languages', language, 'case-studies')
    if os.path.exists(base_dir):
        for f in os.listdir(base_dir):
            if f.endswith('.md'):
                name_lower = os.path.splitext(f)[0].lower()
                if any(word in name_lower for word in vuln_name.lower().split()):
                    return f"languages/{language}/case-studies/{f}"
    return None

def extract_vuln_code_blocks(content, filepath):
    """Extract vulnerable code blocks from markdown content."""
    blocks = []
    
    # Find all section headings and their positions
    headings = [(m.start(), m.group()) for m in re.finditer(r'^#{1,3}\s+(.+)$', content, re.MULTILINE)]
    
    # Pattern 1: Look for code blocks
    code_blocks = list(re.finditer(r'```(\w+)?\n(.*?)```', content, re.DOTALL))
    
    for m in code_blocks:
        lang = m.group(1) if m.group(1) else ''
        code = m.group(2).strip()
        if len(code) < 10:
            continue
        
        block_start = m.start()
        
        # Find the previous heading (section context)
        prev_heading = ''
        for h_pos, h_text in reversed(headings):
            if h_pos < block_start - 10:
                prev_heading = h_text.strip('#').strip()
                break
        
        # Get 150 chars before code block
        ctx_start = max(0, block_start - 150)
        context = content[ctx_start:block_start].strip()
        
        # Determine if this is vulnerable by checking:
        # 1. Context has vulnerability markers
        # 2. Code ITSELF contains 💀
        # 3. Previous heading contains vulnerability indicators
        is_vulnerable = (
            any(w in context.lower() for w in ['zafiyetli', 'tehlikeli', 'unsafe', 'wrong', 'incorrect', 'bad practice', 'güvensiz', 'hata', 'yanlış']) or
            '💀' in code or
            any(w in prev_heading.lower() for w in ['zafiyet', 'vulnerab', 'tehlikeli', 'unsafe', 'hata'])
        )
        
        # Check if this is a fixed version
        is_fixed = (
            any(w in context.lower() for w in ['güvenli', 'fixed', 'secure', 'safe', 'doğrusu', 'correct', 'proper', 'recommended', '✅']) or
            any(w in prev_heading.lower() for w in ['güvenli', 'fixed', 'secure', 'safe', 'correct', 'proper'])
        )
        
        if is_vulnerable and not is_fixed:
            blocks.append({
                'code': code,
                'lang': lang if lang else 'text',
                'heading': prev_heading,
            })
    
    return blocks


def file_to_semgrep_rules(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    
    # Get relative path for KB reference
    rel_path = os.path.relpath(filepath, BASE)
    
    # Get language from path
    path_parts = rel_path.replace('\\', '/').split('/')
    language = 'common'
    for p in path_parts:
        if p in LANG_MAP:
            language = LANG_MAP[p]
            break
    
    # Get title
    title = extract_title(filepath)
    
    # Get severity
    severity = detect_severity(content)
    
    # Get CWE
    cwe = extract_cwe(content)
    
    # Find case study
    case_study = find_case_study(os.path.splitext(os.path.basename(filepath))[0], language)
    
    # Extract vulnerable code blocks
    vuln_blocks = extract_vuln_code_blocks(content, filepath)
    
    rules = []
    
    # Convert each extracted block to a rule
    for i, block in enumerate(vuln_blocks):
        pattern = extract_semgrep_pattern(block['code'], language)
        if not pattern:
            continue
        
        # Generate rule ID
        base_name = os.path.splitext(os.path.basename(filepath))[0].replace('-', '_').lower()
        if len(vuln_blocks) > 1:
            rule_id = f"vibe_{language}_{base_name}_{i+1}"
        else:
            rule_id = f"vibe_{language}_{base_name}"
        
        # Truncate very long rule IDs
        if len(rule_id) > 80:
            rule_id = rule_id[:80]
        
        # Create rule
        rule = {
            'id': rule_id,
            'pattern': pattern,
            'message': f"[VIBE-SEC] {title}\nSeverity: {severity}\nKB: {rel_path}",
            'severity': severity,
            'languages': [language],
            'metadata': {
                'kb_path': rel_path,
                'cwe': cwe if cwe else 'N/A',
            }
        }
        
        if case_study:
            rule['message'] += f"\nCase: {case_study}"
            rule['metadata']['case_study'] = case_study
        
        rules.append(rule)
    
    return rules

def main():
    os.makedirs(OUTPUT, exist_ok=True)
    
    print("="*60)
    print("KB → Semgrep Rule Converter")
    print("="*60)
    
    total_rules = 0
    total_files = 0
    by_language = {}
    errors = []
    
    # Walk through all .md files — only language directories
    lang_dirs = [d for d in os.listdir(BASE) if os.path.isdir(os.path.join(BASE, d)) and d == 'languages']
    
    for root, dirs, files in os.walk(os.path.join(BASE, 'languages')):
        # Skip case-studies and embeddings within languages
        dirs[:] = [d for d in dirs if d not in ['embeddings', 'scripts', 'case-studies']]
            
        for f in files:
            if not f.endswith('.md'):
                continue
            if f == 'index.md' or f == 'case-study-template.md' or f == 'ai-prompt-templates.md' or f == 'hardening-checklist.md':
                continue
            
            filepath = os.path.join(root, f)
            rel_path = os.path.relpath(filepath, BASE)
            
            try:
                rules = file_to_semgrep_rules(filepath)
            except Exception as e:
                errors.append(f"{rel_path}: {e}")
                continue
            
            if rules:
                # Determine language for grouping
                lang = rules[0]['languages'][0]
                by_language.setdefault(lang, []).extend(rules)
                total_rules += len(rules)
                total_files += 1
                
                if total_files % 30 == 0:
                    print(f"  Progress: {total_files} files, {total_rules} rules")
    
    # Write rules per language
    rule_files_created = []
    for lang, rules in sorted(by_language.items()):
        if not rules:
            continue
        
        # Split into chunks of 50 rules max (Semgrep best practice)
        chunk_size = 50
        for i in range(0, len(rules), chunk_size):
            chunk = rules[i:i+chunk_size]
            chunk_num = i // chunk_size
            
            if chunk_num == 0:
                filename = f'vibe-{lang}.yml'
            else:
                filename = f'vibe-{lang}-{chunk_num+1}.yml'
            
            filepath = os.path.join(OUTPUT, filename)
            
            rule_doc = {
                'rules': chunk
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                yaml.dump(rule_doc, f, default_flow_style=False, allow_unicode=True, sort_keys=False, width=120)
            
            rule_files_created.append(filename)
    
    # Generate global dangerous-function rules (one rule file per language)
    global_rules = []
    for lang, funcs in DANGEROUS_FUNCS.items():
        for func in funcs:
            # Clean up regex form to pattern
            pattern = func.replace('\\(', '(').replace('\\{', '{').replace('\\', '')
            clean_name = func.replace('\\(', '').replace('\\{', '').replace('\\.', '_').replace('\\', '_').replace('.*', '').replace('*', '').strip('_').lower()[:25]
            if not clean_name:
                continue
            
            global_rules.append({
                'id': f"vibe_{lang}_dangerous_{clean_name}",
                'pattern': pattern,
                'message': f"[VIBE-SEC-{lang.upper()}] Dangerous pattern: {pattern} — check knowledge base for details",
                'severity': 'ERROR',
                'languages': [lang],
                'metadata': {
                    'type': 'builtin-dangerous',
                    'language': lang,
                }
            })
    
    if global_rules:
        # Split into chunks of 50
        for i in range(0, len(global_rules), 50):
            chunk = global_rules[i:i+50]
            chunk_num = i // 50
            filename = f'vibe-dangerous-{chunk_num+1}.yml' if chunk_num > 0 else 'vibe-dangerous.yml'
            filepath = os.path.join(OUTPUT, filename)
            
            rule_doc = {'rules': chunk}
            with open(filepath, 'w', encoding='utf-8') as f:
                yaml.dump(rule_doc, f, default_flow_style=False, allow_unicode=True, sort_keys=False, width=120)
            rule_files_created.append(filename)
        
        total_global = len(global_rules)
    else:
        total_global = 0
    
    # Create .semgrepconfig.yml for easy use
    config = {'rules': [{'id': f'vibe-{lang}', 'path': f'./{lang}/'} for lang in sorted(by_language.keys())]}
    
    # Write summary
    print(f"\n{'='*60}")
    print(f"CONVERSION COMPLETE")
    print(f"{'='*60}")
    print(f"Files scanned:    {total_files}")
    print(f"Contextual rules: {total_rules}")
    print(f"Built-in rules:   {total_global}")
    print(f"Total rules:      {total_rules + total_global}")
    print(f"Rule files:       {len(rule_files_created)}")
    print(f"Languages:        {len(by_language)}")
    print(f"Output:           {OUTPUT}")
    print()
    
    for lang, rules in sorted(by_language.items()):
        print(f"  {lang}: {len(rules)} rules")
    
    if errors:
        print(f"\nErrors ({len(errors)}):")
        for e in errors[:10]:
            print(f"  {e}")
    
    print(f"\nTo scan a repo:")
    print(f"  semgrep --config {OUTPUT} /path/to/repo")
    
    # Save metadata
    meta = {
        'total_rules': total_rules,
        'total_files': total_files,
        'by_language': {k: len(v) for k, v in sorted(by_language.items())},
        'rule_files': rule_files_created,
        'output_dir': OUTPUT,
    }
    with open(os.path.join(OUTPUT, 'metadata.json'), 'w') as f:
        json.dump(meta, f, indent=2)
    
    return meta

if __name__ == '__main__':
    main()
