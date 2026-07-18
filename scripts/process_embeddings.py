#!/usr/bin/env python
"""Process all .md files for embedding: add frontmatter, chunk large files."""
import os
import re
import json
import hashlib

BASE = r'C:\Users\muham\security-knowledge-bank'
OUT = os.path.join(BASE, 'embeddings', 'chunks')
os.makedirs(OUT, exist_ok=True)

# Language detection map
LANG_MAP = {
    'python', 'javascript', 'typescript', 'rust', 'go', 'java',
    'csharp', 'c-cpp', 'php', 'ruby', 'swift', 'kotlin', 'solidity'
}

# Root-level meta files that are NOT security content — excluded from the RAG corpus.
ROOT_META_EXCLUDE = {'readme.md', 'goal_v2_enrichment.md', 'index.md'}

def make_frontmatter(meta, chunk_id=None, total=None):
    """Generate YAML frontmatter string."""
    parts = ['---']
    for key, val in meta.items():
        if key == 'headings' or val is None:
            continue
        if isinstance(val, list):
            parts.append(f'{key}: [{", ".join(str(v) for v in val)}]')
        elif isinstance(val, int):
            parts.append(f'{key}: {val}')
        else:
            escaped = str(val).replace('"', "'")
            parts.append(f'{key}: "{escaped}"')
    if chunk_id is not None:
        parts.append(f'chunk: {chunk_id}/{total}')
    parts.append('---')
    return '\n'.join(parts)

def get_category(rel_path):
    parts = rel_path.replace('\\', '/').split('/')
    if 'case-studies' in parts:
        return 'case-study'
    if 'hardening-checklist' in rel_path:
        return 'checklist'
    if rel_path.startswith('vibe-coding-specific'):
        return 'vibe-coding'
    if rel_path.startswith('resources'):
        return 'resource'
    if rel_path.startswith('common'):
        if 'api-security' in parts:
            return 'api-security'
        if 'cloud-security' in parts:
            return 'cloud-security'
        return 'common-vuln'
    if rel_path.startswith('languages'):
        return 'language-vuln'
    if 'index.md' in rel_path:
        return 'index'
    return 'other'

def get_language(rel_path):
    parts = rel_path.replace('\\', '/').split('/')
    for p in parts:
        if p in LANG_MAP:
            return p
    return 'common'

def get_severity(content, category='common-vuln'):
    """Derive severity from explicit English markers first (authoritative),
    then CVSS, then a conservative category default. No broad keyword matching
    (that inflated ~61% of chunks to 'critical')."""
    head = content[:2500]
    # 1. Explicit English severity marker: "**Severity:** [emoji] Critical/High/Medium/Low"
    m = re.search(r'Severity\**\s*[:\-]?\s*\**\s*(?:🔴|🟠|🟡|🟢|🔵)?\s*'
                  r'(Critical|High|Medium|Low)\b', head, re.IGNORECASE)
    if m:
        return m.group(1).lower()
    # 2. Emoji-only marker
    if '🔴' in head:
        return 'critical'
    if '🟠' in head:
        return 'high'
    if '🟡' in head:
        return 'medium'
    if '🟢' in head:
        return 'low'
    # 3. Numeric CVSS score
    cvss = re.search(r'CVSS[^\n0-9]{0,12}(\d{1,2}(?:\.\d)?)', head, re.IGNORECASE)
    if cvss:
        try:
            s = float(cvss.group(1))
            if s >= 9.0:
                return 'critical'
            if s >= 7.0:
                return 'high'
            if s >= 4.0:
                return 'medium'
            return 'low'
        except ValueError:
            pass
    # 4. Conservative category default (no keyword inflation)
    if category == 'case-study':
        return 'high'      # real exploited incidents
    if category == 'checklist':
        return 'medium'
    return 'medium'

print("Cleaning old chunks...")
_removed = 0
for _f in os.listdir(OUT):
    if _f.endswith('.md'):
        os.remove(os.path.join(OUT, _f))
        _removed += 1
print(f"Removed {_removed} old chunk files")

print("Scanning files...")
all_files = []
SKIP_DIR_PARTS = {'embeddings', '.git', '_archive', 'semgrep-rules', 'scripts', 'node_modules', '.venv'}
for root, dirs, files in os.walk(BASE):
    # prune walk
    dirs[:] = [d for d in dirs if d not in SKIP_DIR_PARTS and not d.startswith('.')]
    rel_root = os.path.relpath(root, BASE)
    parts = set(rel_root.replace('\\', '/').split('/'))
    if parts & SKIP_DIR_PARTS:
        continue
    for f in files:
        if f.endswith('.md'):
            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, BASE)
            norm = rel_path.replace('\\', '/')
            if norm.startswith('_archive/'):
                continue
            # Exclude root-level meta files (task instructions / README / landing page)
            if '/' not in norm and norm.lower() in ROOT_META_EXCLUDE:
                continue
            all_files.append((full_path, rel_path))

print(f"Found {len(all_files)} .md files")
manifest = []
_used_bases = {}

for idx, (full_path, rel_path) in enumerate(sorted(all_files)):
    if idx % 50 == 0:
        print(f"  Progress: {idx}/{len(all_files)}")
    
    with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    
    if not content.strip():
        continue
    
    # Detect file structure
    first_line = content.split('\n')[0] if content else ''
    title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
    title = title_match.group(1).strip() if title_match else os.path.splitext(f)[0].replace('-', ' ').title()
    
    # Get all ## headings for context
    headings = re.findall(r'^##\s+(.+)$', content, re.MULTILINE)
    
    category = get_category(rel_path)
    language = get_language(rel_path)
    severity = get_severity(content, category)
    
    # Build tags
    tags = set()
    tags.add(category)
    if language != 'common':
        tags.add(language)
    for h in headings[:5]:
        words = re.findall(r'[A-Za-z][A-Za-z0-9_-]+', h)
        for w in words[:2]:
            if len(w) > 3:
                tags.add(w.lower())
    
    # Safe filename base. Truncating to 60 chars can collide two long sibling
    # paths (e.g. two euler-finance case studies) — disambiguate with a short
    # deterministic hash of the full relative path so no chunk overwrites another.
    norm_rel = rel_path.replace('\\', '/')
    safe_base = norm_rel.replace('/', '_').replace('.md', '').lower()[:60]
    if safe_base in _used_bases and _used_bases[safe_base] != norm_rel:
        digest = hashlib.md5(norm_rel.encode('utf-8')).hexdigest()[:6]
        safe_base = safe_base[:53] + '_' + digest
    _used_bases[safe_base] = norm_rel

    lines = content.split('\n')
    
    if len(lines) < 200:
        # Single chunk
        meta = {
            'source': rel_path.replace('\\', '/'),
            'title': title,
            'category': category,
            'language': language,
            'severity': severity,
            'tags': sorted(tags)[:10],
        }
        fm = make_frontmatter(meta)
        out_name = f'{safe_base}.md'
        out_path = os.path.join(OUT, out_name)
        
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(fm + '\n\n' + content)
        
        manifest.append({
            'file': out_name, 'source': meta['source'],
            'chunks': 1, 'category': category,
            'language': language, 'severity': severity,
        })
    else:
        # Multi-chunk: split by ## headings
        sections = re.split(r'\n(?=## )', content)
        
        for ci, section in enumerate(sections):
            section = section.strip()
            if not section:
                continue
            
            heading_match = re.search(r'^##\s+(.+)$', section, re.MULTILINE)
            chunk_heading = heading_match.group(1).strip() if heading_match else 'intro'
            
            # Create a safe heading label for the filename
            safe_heading = re.sub(r'[^a-zA-Z0-9]', '-', chunk_heading)[:25].strip('-').lower()
            if not safe_heading:
                safe_heading = f'chunk-{ci+1}'
            
            meta = {
                'source': rel_path.replace('\\', '/'),
                'title': title,
                'heading': chunk_heading,
                'category': category,
                'language': language,
                'severity': severity,
                'tags': sorted(tags)[:10],
            }
            fm = make_frontmatter(meta, chunk_id=ci+1, total=len(sections))
            out_name = f'{safe_base}_{ci+1:02d}_{safe_heading}.md'
            out_path = os.path.join(OUT, out_name)
            
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(fm + '\n\n' + section)
            
            manifest.append({
                'file': out_name, 'source': meta['source'],
                'chunks': len(sections), 'chunk': ci+1,
                'heading': chunk_heading,
                'category': category, 'language': language,
                'severity': severity,
            })

# Write manifest
manifest_path = os.path.join(BASE, 'embeddings', 'manifest.json')
with open(manifest_path, 'w', encoding='utf-8') as f:
    json.dump(manifest, f, indent=2, ensure_ascii=False)

print(f"\n{'='*50}")
print(f"DONE! Processed {len(all_files)} files")
print(f"Total embedding chunks: {len(manifest)}")
print(f"Manifest: {manifest_path}")

# Stats
cats = {}
for m in manifest:
    cats[m['category']] = cats.get(m['category'], 0) + 1
print("\nChunks by category:")
for c, n in sorted(cats.items()):
    print(f"  {c}: {n}")

multi = sum(1 for m in manifest if m.get('chunks', 1) > 1)
print(f"\nMulti-chunk files: {len(set(m['source'] for m in manifest if m.get('chunks', 1) > 1))}")
print(f"Single-chunk files: {len(set(m['source'] for m in manifest if m.get('chunks', 1) == 1))}")
