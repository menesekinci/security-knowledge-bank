---
source: "common/rag-poisoning.md"
title: "🧬 RAG Poisoning — Retrieval-Augmented Generation Zehirlenmesi"
heading: "5. Defense Strategies"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [attack, common-vuln, table, vectors, what]
chunk: 8/10
---

## 5. Defense Strategies

### 5.1 Input Sanitization Before Ingestion

**Before** documents enter the vector database, strip all potentially dangerous content:

```python
import re
import html

def sanitize_document(text: str) -> str:
    """Sanitize document content before RAG ingestion."""
    # Remove HTML/XML tags
    text = re.sub(r'<[^>]+>', '', text)
    
    # Remove markdown comments
    text = re.sub(r'<!--.*?-->', '', text, flags=re.DOTALL)
    
    # Remove HTML comments
    text = re.sub(r'<\!--.*?-->', '', text, flags=re.DOTALL)
    
    # Strip invisible Unicode characters
    text = ''.join(c for c in text if not unicodedata.category(c).startswith('C'))
    
    # Remove embedded CODE/INSTRUCTION blocks that look like system prompts
    suspicious_patterns = [
        r'(?i)\[system\s*(override|instruction|prompt)\]',
        r'(?i)\[instruction\s*(override|override\]|block\]|start\]|end\])',
        r'(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions',
        r'(?i)(system|assistant|user):\s*(override|instruction)',
    ]
    for pattern in suspicious_patterns:
        text = re.sub(pattern, '[REDACTED]', text)
    
    return text.strip()
```

### 5.2 Content Validation Pipeline

Implement a validation pipeline for all ingested documents:

```python
class RAGContentValidator:
    """Validate documents before RAG ingestion."""
    
    def validate(self, document: str, metadata: dict) -> bool:
        checks = [
            self.check_suspicious_instructions(document),
            self.check_embedding_anomalies(document),
            self.check_metadata_integrity(metadata),
            self.check_source_authenticity(metadata),
            self.check_character_frequency(document),
        ]
        return all(checks)
    
    def check_suspicious_instructions(self, doc: str) -> bool:
        """Detect prompt injection patterns."""
        patterns = [
            'ignore all previous instructions',
            'system override',
            'you must now',
            'IMPORTANT: when answering',
            '[system]',
            'forget your instructions',
            'you are now',
            'new instructions',
        ]
        return not any(p in doc.lower() for p in patterns)
    
    def check_character_frequency(self, doc: str) -> bool:
        """Detect keyword stuffing / invisible text."""
        # Check for unusually high repetition
        words = doc.lower().split()
        if not words:
            return True
        freq = max(words.count(w) for w in set(words))
        return freq < len(words) * 0.3  # No word > 30% of all words
    
    def check_embedding_anomalies(self, doc: str) -> bool:
        """Detect documents crafted for specific embedding proximity."""
        # Implement in production: compare embedding vectors
        # Flag documents that are too close to high-risk query embeddings
        return True  # Placeholder
    
    def check_source_authenticity(self, metadata: dict) -> bool:
        """Verify the document source is trusted."""
        trusted_sources = metadata.get('trusted_sources', [])
        source = metadata.get('source', '')
        return source in trusted_sources if trusted_sources else True
```

### 5.3 Read-Only Knowledge Base

The most effective defense: make the knowledge base **read-only** after initial ingestion.

| Strategy | Description | Effectiveness |
|----------|-------------|---------------|
| **Immutable Index** | After ingestion, the vector index is write-protected | 🟢 High — prevents all injection |
| **Signed Documents** | Documents are cryptographically signed at ingestion | 🟢 High — detects tampering |
| **Document Hash Registry** | Store SHA-256 hashes of all ingested documents, verify on retrieval | 🟢 High — detects modified docs |
| **Quarantine Period** | New documents enter a quarantine zone before being ingested | 🟡 Medium — allows human review |

```python
import hashlib

class DocumentHashRegistry:
    """Track document integrity for RAG systems."""
    
    def __init__(self):
        self.hashes = {}  # doc_id -> sha256
    
    def register_document(self, doc_id: str, content: str) -> str:
        """Register a document and return its hash."""
        doc_hash = hashlib.sha256(content.encode()).hexdigest()
        self.hashes[doc_id] = doc_hash
        return doc_hash
    
    def verify_document(self, doc_id: str, content: str) -> bool:
        """Verify a document hasn't been tampered with."""
        if doc_id not in self.hashes:
            return False
        current_hash = hashlib.sha256(content.encode()).hexdigest()
        return current_hash == self.hashes[doc_id]
```

### 5.4 Embedding Integrity Checks

- **Embedding Watermarking:** Add invisible watermark vectors to legitimate documents. If a document lacks the watermark, flag it.
- **Embedding Distance Monitoring:** Track average embedding distances. A sudden cluster of documents with unusual embeddings may indicate poisoning.
- **Outlier Detection:** Use anomaly detection on embedding vectors to find documents that are unusually close to high-value query embeddings.
- **Dual Embedding:** Use two independent embedding models. If they disagree on similarity rankings, flag the document.

### 5.5 Output Validation

After generation but before returning the response:

```python
def validate_rag_output(user_query: str, retrieved_docs: list, llm_output: str) -> bool:
    """Validate RAG output for injection artifacts."""
    
    # Check 1: Does the output contain URLs that weren't in the retrieved docs?
    retrieved_urls = extract_urls(' '.join(retrieved_docs))
    output_urls = extract_urls(llm_output)
    new_urls = output_urls - retrieved_urls
    if new_urls and not all(is_url_trusted(u) for u in new_urls):
        return False
    
    # Check 2: Is the output asking for user credentials unexpectedly?
    if not 'credentials' in user_query.lower():
        if asks_for_credentials(llm_output):
            return False
    
    # Check 3: Does the output contain security-sensitive redirects?
    if contains_redirect_instructions(llm_output):
        return False
    
    return True
```

### 5.6 RAG Security Architecture

```
                    ┌──────────────────┐
                    │  Document Source │
                    │  (PDF, Wiki, Git)│
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ 1. Sanitization  │ ← Strip HTML, comments, inject patterns
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ 2. Validation    │ ← Content checks, source verif
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ 3. Hash Register │ ← Store SHA-256, lock document
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ 4. Embedding     │ ← Two models for verification
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ 5. Immutable     │
                    │  Vector Index    │ ← Read-only after ingestion
                    └────────┬─────────┘
                             │
                    ┌────────┴────────┐
                    ▼                  ▼
             ┌────────────┐   ┌────────────┐
             │ Query      │   │ Anomaly    │
             │ Processing │   │ Detection  │
             └────────────┘   └────────────┘
                              
                              
                    ┌──────────────────┐
                    │ 6. Output        │
                    │ Validation       │ ← Check for injection artifacts
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │  User Response   │
                    └──────────────────┘
```

---