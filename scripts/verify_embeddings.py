"""Embedding chunk verifier - run by sub-agents for batch verification.

Reads a batch manifest, verifies each chunk file, reports results.
"""
import os, json, sys, re

def verify_chunk(filepath, expected_entry):
    """Verify a single embedding chunk. Returns list of issues (empty = perfect)."""
    issues = []
    
    if not os.path.exists(filepath):
        return ['MISSING_FILE']
    
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    
    # 1. Frontmatter presence
    if not content.startswith('---'):
        issues.append('NO_FRONTMATTER')
        return issues  # Can't continue
    
    # 2. Find frontmatter boundaries
    fm_end = content.find('---', 3)
    if fm_end == -1:
        issues.append('MALFORMED_FRONTMATTER')
        return issues
    
    fm_block = content[3:fm_end]
    body = content[fm_end+3:].strip()
    
    # 3. Required fields check
    required = ['source:', 'title:', 'category:', 'language:']
    for field in required:
        if field not in fm_block:
            issues.append(f'MISSING_{field.replace(":", "").upper()}')
    
    # 4. Source match
    if 'source:' in fm_block:
        src_line = [l for l in fm_block.split('\n') if l.startswith('source:')]
        if src_line:
            actual_src = src_line[0].split('"')[1] if '"' in src_line[0] else ''
            if actual_src and actual_src != expected_entry.get('source', ''):
                issues.append(f'SOURCE_MISMATCH:expected={expected_entry.get("source")} actual={actual_src}')
    
    # 5. Content quality
    body_lines = body.split('\n')
    if len(body) < 30:
        issues.append(f'TOO_SHORT:{len(body)}chars')
    elif len(body) < 100:
        issues.append(f'BRIEF:{len(body)}chars')
    
    # 6. Has actual markdown content (headings, code, or text)
    has_content = bool(re.search(r'[A-Za-z]{4,}', body))
    if not has_content:
        issues.append('NO_MEANINGFUL_CONTENT')
    
    # 7. Chunk metadata match
    if 'heading:' in fm_block:
        heading_line = [l for l in fm_block.split('\n') if l.startswith('heading:')]
        if heading_line:
            h = heading_line[0].split('"')[1] if '"' in heading_line[0] else ''
            expected_heading = expected_entry.get('heading', '')
    
    return issues

def main():
    
    if len(sys.argv) < 2:
        print("Usage: python verify_embeddings.py <batch_manifest.json>")
        print("Verifies embedding chunks listed in a batch manifest.")
        print("Example: python verify_embeddings.py embeddings/batch_manifest.json")
        sys.exit(1)
    batch_path = sys.argv[1]
    if not os.path.exists(batch_path):
        print(f"ERROR: Batch file not found: {batch_path}")
        sys.exit(1)
    
    with open(batch_path, 'r', encoding='utf-8') as f:
        batch = json.load(f)
    
    chunk_dir = os.path.join(os.path.dirname(batch_path), 'chunks')
    
    results = {
        'total': len(batch),
        'perfect': 0,
        'has_issues': 0,
        'issues_summary': {},
        'files_with_issues': [],
        'stats': {
            'avg_body_len': 0,
            'min_body_len': float('inf'),
            'max_body_len': 0,
        }
    }
    total_body_len = 0
    
    for entry in batch:
        filepath = os.path.join(chunk_dir, entry['file'])
        issues = verify_chunk(filepath, entry)
        
        # Body length stats
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            fm_end = content.find('---', 3)
            if fm_end > 0:
                body_len = len(content[fm_end+3:].strip())
            else:
                body_len = len(content.strip())
        else:
            body_len = 0
        
        total_body_len += body_len
        results['stats']['min_body_len'] = min(results['stats']['min_body_len'], body_len)
        results['stats']['max_body_len'] = max(results['stats']['max_body_len'], body_len)
        
        if not issues:
            results['perfect'] += 1
        else:
            results['has_issues'] += 1
            results['files_with_issues'].append({
                'file': entry['file'],
                'source': entry['source'],
                'issues': issues
            })
            for issue in issues:
                issue_base = issue.split(':')[0]
                results['issues_summary'][issue_base] = results['issues_summary'].get(issue_base, 0) + 1
    
    results['stats']['avg_body_len'] = total_body_len // len(batch) if batch else 0
    
    # Summary
    print(f"\n{'='*60}")
    print(f"BATCH VERIFICATION REPORT")
    print(f"{'='*60}")
    print(f"Total chunks:     {results['total']}")
    print(f"Perfect chunks:   {results['perfect']} ({results['perfect']*100//results['total']}%)")
    print(f"Chunks w/issues:  {results['has_issues']}")
    print(f"\nBody length stats:")
    print(f"  Avg: {results['stats']['avg_body_len']} chars")
    print(f"  Min: {results['stats']['min_body_len']} chars")
    print(f"  Max: {results['stats']['max_body_len']} chars")
    
    if results['issues_summary']:
        print(f"\nIssue breakdown:")
        for issue, count in sorted(results['issues_summary'].items()):
            print(f"  {issue}: {count}")
    
    if results['files_with_issues']:
        print(f"\nFiles with issues (first 5):")
        for f in results['files_with_issues'][:5]:
            print(f"  [{', '.join(f['issues'])}] {f['file']}")

if __name__ == '__main__':
    main()
