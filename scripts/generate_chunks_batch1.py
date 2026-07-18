"""Generate missing chunk files for batch_1.json from source markdown files."""
import json
import os
import re

KB_ROOT = r"C:\Users\muham\security-knowledge-bank"
BATCH_PATH = os.path.join(KB_ROOT, "embeddings", "batch_1.json")
CHUNKS_DIR = os.path.join(KB_ROOT, "chunks")

os.makedirs(CHUNKS_DIR, exist_ok=True)

with open(BATCH_PATH, 'r', encoding='utf-8') as f:
    batch = json.load(f)

def extract_title(source_content):
    """Extract the first h1 title from the source."""
    m = re.search(r'^#\s+(.+)$', source_content, re.MULTILINE)
    return m.group(1).strip() if m else os.path.basename(source_path).replace('.md', '')

def extract_section(content, heading, is_intro=False, all_headings=None):
    """Extract section content based on heading.
    
    For intro: content from start to first ## heading.
    For regular: content from ## <heading> to next ## heading at same level.
    """
    if is_intro or heading == "intro":
        # Intro is from start to first ## heading
        m = re.search(r'^##\s+', content, re.MULTILINE)
        if m:
            return content[:m.start()].strip()
        return content.strip()
    
    # Find the heading
    # The heading in the batch may not exactly match the markdown heading
    # due to truncation/formatting. We need to do a fuzzy match.
    lines = content.split('\n')
    
    # Find heading lines (## or ###)
    heading_candidates = []
    for i, line in enumerate(lines):
        m = re.match(r'^(#{2,3})\s+(.*)', line)
        if m:
            level = len(m.group(1))
            text = m.group(2).strip()
            heading_candidates.append((i, level, text))
    
    if not heading_candidates:
        return content.strip()
    
    # Try exact match first, then prefix match
    target_idx = None
    target_level = 2
    
    for i, level, text in heading_candidates:
        if text == heading:
            target_idx = i
            target_level = level
            break
    
    if target_idx is None:
        # Try prefix match (batch headings may be truncated)
        best_len = 0
        for i, level, text in heading_candidates:
            # Check if batch heading starts with this section heading or vice versa
            if heading.startswith(text) or text.startswith(heading):
                if len(text) > best_len:
                    target_idx = i
                    target_level = level
                    best_len = len(text)
                elif len(text) == best_len and i > target_idx:
                    target_idx = i
                    target_level = level
    
    if target_idx is None:
        # Try case-insensitive
        heading_lower = heading.lower()
        for i, level, text in heading_candidates:
            if text.lower() == heading_lower:
                target_idx = i
                target_level = level
                break
    
    if target_idx is None:
        # Fallback: try fuzzy by looking for key words in the heading
        heading_words = set(heading.lower().split()[:3])
        for i, level, text in heading_candidates:
            text_words = set(text.lower().split())
            if heading_words & text_words:  # any word overlap
                match_ratio = len(heading_words & text_words) / max(len(heading_words), 1)
                if match_ratio >= 0.5:
                    target_idx = i
                    target_level = level
                    break
    
    if target_idx is None:
        # Last resort: return whole content with a warning
        print(f"  WARNING: Could not find heading '{heading}' in source, using full content")
        return content.strip()
    
    # Extract from this heading to next heading at same or higher level
    result_lines = [lines[target_idx]]
    for i in range(target_idx + 1, len(lines)):
        line = lines[i]
        m = re.match(r'^(#{2,3})\s+(.*)', line)
        if m:
            level = len(m.group(1))
            if level <= target_level:
                break
        result_lines.append(line)
    
    return '\n'.join(result_lines).strip()

def create_frontmatter(entry, title):
    """Create YAML frontmatter for a chunk file."""
    fm = []
    fm.append(f'source: "{entry["source"]}"')
    fm.append(f'title: "{title}"')
    fm.append(f'category: "{entry["category"]}"')
    fm.append(f'language: "{entry["language"]}"')
    
    if entry.get("severity") and entry["severity"] != "unknown":
        fm.append(f'severity: "{entry["severity"]}"')
    
    if "chunk" in entry:
        fm.append(f'chunk: {entry["chunk"]}')
        fm.append(f'total_chunks: {entry["chunks"]}')
    
    if "heading" in entry and entry["heading"]:
        # Escape quotes in heading
        h = entry["heading"].replace('"', '\\"')
        fm.append(f'heading: "{h}"')
    
    return '\n'.join(fm)

stats = {'total': len(batch), 'created': 0, 'skipped': 0, 'errors': 0, 'missing_source': 0}

for entry in batch:
    chunk_file = entry['file']
    source_path = os.path.join(KB_ROOT, entry['source'])
    chunk_path = os.path.join(CHUNKS_DIR, chunk_file)
    
    # Skip if already exists (don't overwrite)
    if os.path.exists(chunk_path):
        stats['skipped'] += 1
        continue
    
    if not os.path.exists(source_path):
        print(f"ERROR: Source file not found: {source_path}")
        stats['missing_source'] += 1
        stats['errors'] += 1
        continue
    
    try:
        with open(source_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        
        # Determine section to extract
        heading = entry.get('heading', '')
        has_chunks = entry.get('chunks', 1) > 1
        is_intro = (heading == 'intro' or heading == '')
        
        if not heading and not is_intro:
            # Single chunk - use whole file
            body = content.strip()
        else:
            body = extract_section(content, heading, is_intro=is_intro)
        
        if not body:
            print(f"  WARNING: Empty body for {chunk_file} (heading='{heading}')")
            body = content.strip()
        
        # Extract title for frontmatter
        title = extract_title(content)
        
        # Build chunk content
        frontmatter = create_frontmatter(entry, title)
        chunk_content = f"---\n{frontmatter}\n---\n\n{body}"
        
        with open(chunk_path, 'w', encoding='utf-8') as f:
            f.write(chunk_content)
        
        stats['created'] += 1
        if stats['created'] % 20 == 0:
            print(f"  Progress: {stats['created']}/{len(batch)} chunks created...")
        
    except Exception as e:
        print(f"ERROR creating {chunk_file}: {e}")
        stats['errors'] += 1

print(f"\n{'='*60}")
print("CHUNK GENERATION SUMMARY")
print(f"{'='*60}")
print(f"Total entries:   {stats['total']}")
print(f"Created:         {stats['created']}")
print(f"Skipped (exist): {stats['skipped']}")
print(f"Errors:          {stats['errors']}")
print(f"Missing source:  {stats['missing_source']}")
