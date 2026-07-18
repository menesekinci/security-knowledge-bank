"""Clean output dir and regenerate."""
import os, sys, shutil

OUTPUT = r'C:\Users\muham\security-knowledge-bank\semgrep-rules'

# Remove all existing rule files
if os.path.exists(OUTPUT):
    for f in os.listdir(OUTPUT):
        if f.endswith('.yml') or f.endswith('.json'):
            os.remove(os.path.join(OUTPUT, f))
    print(f"Cleaned {len(os.listdir(OUTPUT))} files from output dir")
else:
    os.makedirs(OUTPUT)

print("Ready for fresh generation")
