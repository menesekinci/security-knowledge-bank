"""Split embedding manifest into 3 batches for parallel verification."""
import json
import os

BASE = r'C:\Users\muham\security-knowledge-bank'
manifest_path = os.path.join(BASE, 'embeddings', 'manifest.json')

with open(manifest_path, 'r', encoding='utf-8') as f:
    manifest = json.load(f)

total = len(manifest)
batch_size = total // 3

print(f"Total chunks: {total}")
print(f"Batch size: {batch_size}")

for i in range(3):
    start = i * batch_size
    end = (i + 1) * batch_size if i < 2 else total
    batch = manifest[start:end]
    
    batch_path = os.path.join(BASE, 'embeddings', f'batch_{i}.json')
    with open(batch_path, 'w', encoding='utf-8') as f:
        json.dump(batch, f, indent=2)
    
    print(f"Batch {i}: chunks {start}-{end} ({len(batch)} files) -> {batch_path}")
