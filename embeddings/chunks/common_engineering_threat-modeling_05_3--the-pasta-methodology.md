---
source: "common/engineering/threat-modeling.md"
title: "Threat Modeling"
heading: "3. The PASTA Methodology"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, linddun, pasta, stride, table, what]
chunk: 5/13
---

## 3. The PASTA Methodology

PASTA (Process for Attack Simulation and Threat Analysis) is a risk-centric methodology developed by Tony UcedaVélez. It is more systematic and attacker-focused than STRIDE.

### The 7 Stages of PASTA

```
Stage 1: Define Objectives
    ↓
Stage 2: Define Technical Scope
    ↓
Stage 3: Application Decomposition
    ↓
Stage 4: Threat Analysis
    ↓
Stage 5: Vulnerability Analysis
    ↓
Stage 6: Attack Modeling
    ↓
Stage 7: Risk & Impact Analysis
```

#### Stage 1: Define Objectives

Align security goals with business objectives. Questions:
- What are the compliance requirements? (PCI-DSS, SOC 2, HIPAA, GDPR)
- What is the business risk appetite?
- What are the key assets to protect?
- What is the worst-case business impact of a breach?

**Output:** Business impact analysis, security requirements document.

#### Stage 2: Define Technical Scope

Define the boundaries of the analysis. Questions:
- What components are in scope? What is explicitly out of scope?
- What are the dependencies? (third-party APIs, libraries, infrastructure)
- What data enters and leaves the scope?
- What trust boundaries exist?

**Output:** Scope diagram, asset inventory, dependency list.

#### Stage 3: Application Decomposition

Break the application into functional components. Activities:
- Create detailed Data Flow Diagrams (see §6)
- Map trust boundaries
- Enumerate entry points (APIs, web endpoints, message queues, file ingestion)
- Identify assets and data classifications

**Output:** Decomposition diagram, entry point list, asset classification.

#### Stage 4: Threat Analysis

Identify threats using intelligence, not just imagination. Activities:
- Gather threat intelligence relevant to the technology stack
- Use STRIDE, CAPEC, or ATT&CK as classification taxonomies
- Analyze each asset from an attacker's perspective: "How would I steal this?"
- Map threats to business impact from Stage 1

**Output:** Threat list with classification, threat-to-asset mapping.

#### Stage 5: Vulnerability Analysis

Map threats to specific vulnerabilities. Activities:
- Correlate threats with known vulnerability patterns (CWE)
- Check the technology stack against known CVEs
- Static analysis of the design — where are the weak points?
- Consider zero-day potential in critical paths

**Output:** Vulnerability map, CWE-to-component mapping.

#### Stage 6: Attack Modeling

Simulate realistic attack paths. Activities:
- Create attack trees — "What steps would defeat this control?"
- Model attack chains — multiple steps chained together
- Use tools like OWASP Threat Dragon or Microsoft TM Tool to visualize
- Calculate likelihood and impact using CVSS or custom scoring

**Output:** Attack trees, attack paths, likelihood scores.

#### Stage 7: Risk & Impact Analysis

Make decisions based on the analysis. Activities:
- Calculate residual risk after applying existing controls
- Prioritize mitigation backlog
- Produce a "Top N" risk list for executive review
- Document accepted risks with explicit sign-off

**Output:** Risk register, mitigation roadmap, executive summary.

### When to Use PASTA

PASTA is best for:
- **Complex systems** with multiple components and data flows
- **High-risk applications** (fintech, healthcare, critical infrastructure)
- **Regulated environments** where risk quantification is expected
- **Mature security programs** that have already mastered STRIDE

---