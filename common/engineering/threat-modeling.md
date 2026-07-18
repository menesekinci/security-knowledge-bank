# Threat Modeling

> **Audience:** Software engineers, architects, product managers, security champions
> **Purpose:** Systematic methodology for identifying, documenting, and mitigating security threats during design
> **Reading time:** 20–25 minutes

---

## Table of Contents

1. [What Is Threat Modeling?](#1-what-is-threat-modeling)
2. [The STRIDE Methodology](#2-the-stride-methodology)
3. [The PASTA Methodology](#3-the-pasta-methodology)
4. [The LINDDUN Methodology](#4-the-linddun-methodology)
5. [Choosing a Methodology](#5-choosing-a-methodology)
6. [Data Flow Diagrams](#6-data-flow-diagrams)
7. [Practical Exercise: Threat Modeling a Web App](#7-practical-exercise-threat-modeling-a-web-app)
8. [Tools for Threat Modeling](#8-tools-for-threat-modeling)
9. [Integrating Threat Modeling into Agile](#9-integrating-threat-modeling-into-agile)
10. [Common Mistakes](#10-common-mistakes)
11. [Further Reading](#11-further-reading)

---

## 1. What Is Threat Modeling?

Threat modeling is a structured approach to identifying what could go wrong in a system from a security perspective — *before* it ships. It is not a penetration test, a code review, or a compliance checkbox. It is a design-time activity that answers four questions:

1. **What are we building?** (System context, trust boundaries, data flows)
2. **What can go wrong?** (Threats — the "attack" side of the equation)
3. **What are we doing about it?** (Mitigations — the "defense" side)
4. **Did we do a good job?** (Validation — tests, reviews, residual risk acceptance)

### Why Threat Model?

| Reason | Explanation |
|---|---|
| **Shift left** | Finding a design flaw in production costs 100x more than finding it during design |
| **Shared mental model** | Developers, architects, security, and product align on what the system does and where risk lives |
| **Defensible decisions** | Documented threat models justify why a control exists (or why a risk was accepted) |
| **Test case generation** | Threats translate directly to security test scenarios and abuse cases |
| **Compliance evidence** | Regulators and auditors increasingly expect evidence of threat modeling |

---

## 2. The STRIDE Methodology

STRIDE was developed by Microsoft in the late 1990s as part of their Security Development Lifecycle (SDL). It classifies threats into six categories, one per letter of the acronym.

### STRIDE Categories

| Category | Definition | Violates | Example |
|---|---|---|---|
| **S**poofing | Pretending to be someone or something else | Authentication | Attacker forges a JWT claiming to be `admin` |
| **T**ampering | Modifying data or code without authorization | Integrity | Attacker modifies a database row via SQL injection |
| **R**epudiation | Denying having performed an action | Non-repudiation | Operator deletes logs after performing unauthorized action |
| **I**nformation Disclosure | Exposing data to unauthorized parties | Confidentiality | Stack trace reveals database connection string |
| **D**enial of Service | Disrupting service availability | Availability | Attacker floods login endpoint with slow requests |
| **E**levation of Privilege | Gaining unauthorized access or permissions | Authorization | Regular user exploits a path traversal to access admin API |

### STRIDE Per Element

The most effective way to apply STRIDE is to examine each element of a Data Flow Diagram (see §6) against each category:

| DFD Element | S | T | R | I | D | E | Focus |
|---|---|---|---|---|---|---|---|
| **External Entity** | ✓ | | ✓ | | | | Who is this? Can they lie about who they are? |
| **Process** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Everything — processes are ground zero for threats |
| **Data Store** | | ✓ | ✓ | ✓ | ✓ | | Is data protected at rest? Can it be tampered? |
| **Data Flow** | | ✓ | | ✓ | | | Is data in transit encrypted? Can it be intercepted? |

### How to Run a STRIDE Session

1. **Draw the DFD** (see §6) with trust boundaries marked.
2. **Walk each element** and ask: "What STRIDE threats apply here?"
3. **Document each threat** in a table:
   ```
   | ID | Element | STRIDE | Threat Description | Mitigation | Severity | Status |
   ```
4. **Prioritize** using DREAD or CVSS scoring (see §2.1 below).
5. **Assign mitigations** — for each threat, decide: mitigate (implement control), transfer (insurance/SLA), eliminate (redesign), or accept (document risk).

#### Prioritization: DREAD (Optional)

Microsoft also defined DREAD for ranking threats:

| Letter | Meaning | Scale (1–10) |
|---|---|---|
| **D**amage Potential | How severe is the damage? | 1=minor info leak, 10=complete compromise |
| **R**eproducibility | How easily can the attack be reproduced? | 1=extremely hard, 10=easy script |
| **E**xploitability | How much skill/access is needed? | 1=requires expert+phys access, 10=unauthenticated |
| **A**ffected Users | How many users are impacted? | 1=very few, 10=all |
| **D**iscoverability | How easy is it to find the vulnerability? | 1=very hard, 10=publicly known |

**Total = (D + R + E + A + D) / 5**

> **Note:** DREAD is subjective. Many teams now prefer CVSS v3+ scoring for its wider industry calibration.

### STRIDE Variants

- **STRIDE-per-Element** — process each DFD element independently (most common)
- **STRIDE-per-Interaction** — examine each data flow between elements (better for complex microservice architectures)
- **STRIDE-LM** — STRIDE with "Lateral Movement" added for network-centric threat models

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

## 4. The LINDDUN Methodology

LINDDUN (derived from **L**inkability, **I**dentifiability, **N**on-repudiation, **D**etectability, **D**isclosure of information, **U**nawareness, **N**on-compliance) is a privacy-focused threat modeling methodology from KU Leuven.

### LINDDUN Categories

| Category | Meaning | Privacy Principle |
|---|---|---|
| **L**inkability | Can two data points be linked to the same individual? | Unlinkability |
| **I**dentifiability | Can an individual be identified from the data? | Anonymity & Pseudonymity |
| **N**on-repudiation | Can a user be held accountable (privacy concern)? | Plausible deniability |
| **D**etectability | Can an attacker determine if data about a person exists? | Undetectability & Unobservability |
| **D**isclosure of Information | Is personal data exposed to unauthorized parties? | Confidentiality |
| **U**nawareness | Is the user informed and in control? | User awareness & consent |
| **N**on-compliance | Does the system violate privacy regulations? | Compliance |

### LINDDUN Process

1. **Model the system** — create DFDs annotated with personal data flows (which flows carry PII?).
2. **Map privacy threats** — for each DFD element, ask "Which LINDDUN threats apply?"
3. **Identify mitigation strategies** — data minimization, anonymization, aggregation, consent interfaces, deletion capabilities.
4. **Prioritize** — focus on threats with legal/compliance impact first.
5. **Implement privacy controls** — pet names, differential privacy, data retention limits, right-to-deletion workflows.
6. **Validate** — privacy impact assessment (PIA), data protection officer (DPO) review.

### When to Use LINDDUN

- **GDPR/HIPAA/PIPEDA compliance** — any system processing personal data
- **Consumer-facing products** — apps, IoT devices, platforms with user accounts
- **Data analytics pipelines** — where aggregate data could be de-anonymized
- **Biometric or health-data systems** — highest privacy risk

---

## 5. Choosing a Methodology

| Factor | STRIDE | PASTA | LINDDUN |
|---|---|---|---|
| **Focus** | Security threats | Risk-based analysis | Privacy threats |
| **Depth** | Medium | High | Medium-High |
| **Time required** | 1–3 hours per component | 2–5 days for full process | 1–3 hours per data flow |
| **Who leads** | Engineer + security champion | Dedicated security architect | Privacy engineer / DPO |
| **Best for** | Web apps, APIs, microservices | Complex, critical, regulated systems | Systems handling PII |
| **Deliverable** | Threat list with mitigations | Risk register + attack trees | Privacy threat model + PIA |
| **Learning curve** | Low | High | Medium |

### Hybrid Approach

Many mature teams use **STRIDE for sprint-level threat models** (fast, focused) and **PASTA for quarterly deep dives** on critical systems. LINDDUN runs alongside whichever methodology is chosen whenever PII flows are involved.

---

## 6. Data Flow Diagrams

Data Flow Diagrams (DFDs) are the backbone of threat modeling. They describe *what* data moves *where* without prescribing *how* (no implementation details).

### DFD Elements

| Shape | Element | Meaning | STRIDE Relevance |
|---|---|---|---|
| Rectangle | External Entity | User, third-party system, or device outside the system boundary | Spoofing, Repudiation |
| Circle / Rounded Rect | Process | Component that transforms data | All six categories |
| Parallel Lines | Data Store | Database, file, cache, bucket | Tampering, Repudiation, Info Disclosure, DoS |
| Arrow | Data Flow | Movement of data between elements | Tampering, Info Disclosure |
| Dotted Line | Trust Boundary | Boundary between trust zones | All — crossing a boundary adds risk |

### Trust Boundaries

A trust boundary is any point where data moves from a higher-trust zone to a lower-trust zone, or vice versa. **Every trust boundary crossing is a security control point.**

Common trust boundaries:
- **Network boundary:** Public internet → VPC
- **Auth boundary:** Unauthenticated → Authenticated
- **Privilege boundary:** Standard user → Admin
- **Process boundary:** Web server → Database
- **Environment boundary:** Dev → Staging → Production
- **Tenant boundary:** Customer A's data → Customer B's data

### Drawing a DFD: Rules

1. **Start at the boundary.** Draw the system boundary rectangle. Everything inside is in scope.
2. **Add external entities** outside the boundary that interact with the system.
3. **Draw processes** — the internal components.
4. **Add data stores** — where data rests.
5. **Connect with data flows** — arrows that show the direction of data movement.
6. **Mark trust boundaries** — any line where the trust level changes.
7. **Validate** — does every data flow connect two elements? Is every data store reachable?

### Example DFD (Textual)

```
┌───────────────────────────────────── System Boundary ─────────────────────────────────────┐
│                                                                                           │
│  [Browser/User] ───HTTPS──→ [API Gateway] ───gRPC──→ [Order Service] ───SQL──→ [(Orders DB)]  │
│      ↑                          ↓                      │                                   │
│      │                       [Auth Service]             │                                   │
│      │                          │                      │                                   │
│      └──────────────────────────┘                      gRPC                                 │
│                                                          ↓                                   │
│                                                    [Payment Service] ───SQL──→ [(Payment DB)]│
│                                                          │                                   │
│                                                    [Fraud Check API] ←─── HTTP (3rd party)  │
│                                                          │                                   │
│                                                    [Audit Logger] → [(Audit Log)]            │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
Trust boundaries:
1. Browser ↔ API Gateway  (← Internet → VPC)
2. All service-to-service (← internal VPC)
3. Services ↔ Databases     (← application → data tier)
```

---

## 7. Practical Exercise: Threat Modeling a Web App

Let's walk through threat modeling a simple note-taking web application: **NoteVault**.

### Step 1: System Description

- Users register, log in, and create encrypted notes
- Notes stored in PostgreSQL; encryption keys managed by a separate Key Management Service (KMS)
- Frontend: React SPA
- Backend: REST API (Go), JWT-based authentication
- Infrastructure: AWS ECS, RDS PostgreSQL, DynamoDB for sessions
- Third-party: SendGrid for email verification

### Step 2: Draw the DFD

```
[User Browser] ──HTTPS──→ [ALB] ──HTTPS──→ [API Server] ──SQL──→ [(PostgreSQL)]
                      ↑                         │                      │
                      │                         ├──HTTPS──→ [KMS API]  │
                      │                         │                      │
                      │                         └──SMTP──→ [SendGrid]  │
                      │                                              │
                  [DynamoDB Sessions]                            [S3 Backups]
```

Trust boundaries:
- Browser ↔ ALB (Internet → VPC)
- ALB ↔ API Server (VPC internal)
- API Server ↔ PostgreSQL (app → data tier)
- API Server ↔ KMS API (internal → AWS KMS endpoint)
- API Server ↔ SendGrid (VPC → external SaaS)

### Step 3: STRIDE Threats Per Element

#### API Server (Process)

| ID | STRIDE | Threat | Mitigation | Sev |
|---|---|---|---|---|
| T1 | Spoofing | Attacker forges a JWT with stolen signing key | Rotate signing keys, use short-lived tokens, public key pinning | High |
| T2 | Tampering | SQL injection in note content | Parameterized queries, ORM, WAF rule | High |
| T3 | Repudiation | User deletes a note, claims they didn't | Immutable audit log for all note mutations | Medium |
| T4 | Info Disclosure | Error response leaks stack trace with DB hostname | Structured error responses, no stack traces in production | Medium |
| T5 | DoS | Unauthenticated /register endpoint exhaustion | Rate limiting per IP, CAPTCHA, account lockout | Medium |
| T6 | Elevation | User modifies note_id parameter to read another user's note | Ownership check on every read operation: `WHERE user_id = ? AND note_id = ?` | High |

#### PostgreSQL (Data Store)

| ID | STRIDE | Threat | Mitigation | Sev |
|---|---|---|---|---|
| T7 | Tampering | Rogue admin modifies notes directly in DB | Encryption at rest, audit logging, restricted DB access | Medium |
| T8 | Info Disclosure | Backup leaked from S3 contains plaintext notes | Encrypt backups with KMS, restrict S3 bucket policies | High |
| T9 | DoS | Connection pool exhaustion | Connection pooling with max limits, query timeout | Low |

#### Data Flow: API Server → SendGrid

| ID | STRIDE | Threat | Mitigation | Sev |
|---|---|---|---|---|
| T10 | Info Disclosure | API key for SendGrid leaked in logs | Secret scanning in CI, key rotation, log redaction | Medium |
| T11 | Tampering | Man-in-the-middle modifies email verification link | TLS for SMTP (SMTPS or STARTTLS enforced) | Medium |

### Step 4: Prioritize & Assign

**High-severity threats (must-fix before launch):** T1, T2, T6, T8
**Medium-severity (fix within 30 days):** T3, T4, T5, T10, T11
**Low-severity (accept/track):** T9

### Step 5: Create Test Cases

- T2 → SQL injection fuzz tests on all endpoints accepting user input
- T6 → Automated permission tests: user A cannot read/update/delete user B's notes
- T4 → Error handling integration tests: verify no stack traces in production error responses

---

## 8. Tools for Threat Modeling

| Tool | Type | Cost | Best For |
|---|---|---|---|
| **Microsoft Threat Modeling Tool** | Desktop (Windows) | Free | STRIDE-based modeling, DFD creation, automatic threat generation |
| **OWASP Threat Dragon** | Web + Desktop | Free | Cross-platform, STRIDE & LINDDUN, Git-backed model storage |
| **draw.io / diagrams.net** | Web + Desktop | Free | General DFD creation (not threat-specific but flexible) |
| **IriusRisk** | SaaS | Paid | Enterprise threat modeling with risk management workflows |
| **ThreatModeler** | SaaS | Paid | Large organizations, integrates with CI/CD |
| **Toreon Threat Modelling Tool** | SaaS | Paid | Asset-centric modeling, SDLC integration |
| **Structurizr** | DSL-based | Free/Paid | Code-as-diagrams (C4 model), automated DFD generation |
| **Lucidchart** | SaaS | Paid | Collaborative DFDs with threat modeling template library |

### Tool Selection Criteria

- **Team size:** Small teams can use Threat Dragon + draw.io; enterprise needs IriusRisk or ThreatModeler
- **Integration:** Does it plug into Jira, Azure DevOps, GitHub Issues?
- **Granularity:** Do you need per-component threat lists or high-level risk register?
- **Version control:** Can threat models be stored as code (DSL/YAML) and diffed in PR reviews?

---

## 9. Integrating Threat Modeling into Agile

Threat modeling is often seen as a "waterfall" activity, but it works in agile too. The key is **right-sizing** — not every story needs a full PASTA exercise.

### Sprint-Level (Lightweight Threat Modeling)

**When:** Every sprint, for stories that introduce new data flows or new trust boundaries.
**Duration:** 15–30 minutes during sprint planning or design review.
**Format:** "Three questions" — (1) What new data flows are we adding? (2) What trust boundaries are we crossing? (3) What could go wrong with each?
**Output:** 2–3 threats documented in the story's acceptance criteria.

### Release-Level (Standard Threat Modeling)

**When:** Before every major release or feature launch.
**Duration:** 1–2 hours.
**Format:** Full STRIDE-per-element session with a DFD.
**Output:** Threat table, mitigation list, test cases added to release regression suite.

### Quarterly (Deep Dive)

**When:** Once per quarter for critical services.
**Duration:** 1–2 days per system.
**Format:** PASTA stages 1–7 or full STRIDE with attack tree modeling.
**Output:** Risk register update, mitigation roadmap, executive summary.

### Making It Stick

- **Dedicated security champion** in every team — trains on threat modeling, facilitates sessions
- **Threat model in pull requests** — every PR that changes a DFD element must include or update the threat model
- **Threat model as code** — store DFDs and threat tables alongside the source code in `.threat-models/` directory
- **Gamify it** — "Threat of the Sprint" award for the best threat identified

---

## 10. Common Mistakes

### Mistake 1: Threat Modeling Too Late

Waiting until the system is built to threat model means the design is already locked in. Findings become "won't fix" because refactoring is too expensive. **Do it during design, not after implementation.**

### Mistake 2: Analysis Paralysis

Trying to enumerate *every possible* threat leads to a 200-item threat list that nobody reads. A threat model with 20 well-prioritized threats is more useful than one with 200 unprioritized ones. **Focus on the top 5–10 critical threats first.**

### Mistake 3: Ignoring Human Elements

Threat models often assume rational, technical attackers. Real-world attack chains include social engineering, insider threats, and operational mistakes. **Include "operator error" and "insider" as threat actors.**

### Mistake 4: One-and-Done

A threat model is a living document. As the system evolves — new features, new dependencies, new deployment model — the threat model must evolve too. **Treat threat models like code: versioned, reviewed, updated.**

### Mistake 5: Only Thinking About External Attackers

Many damaging attacks come from insiders or from compromised third-party dependencies. Your threat model should include threat actors at every trust level: anonymous user, authenticated user, partner integration, employee, contractor, system administrator.

### Mistake 6: Not Validating Mitigations

"If we use JWT, it's secure" — but is the JWT library correctly configured? Is the signing key rotated? Are revoked tokens checked? **A mitigation in a threat model is a hypothesis until it is tested.**

### Mistake 7: Document Dumps

Putting the threat model in a PDF that lives in a wiki folder nobody visits means it has no effect. **The threat model should directly drive backlog items, test cases, and architecture decisions.**

### Mistake 8: Over-Focusing on Technology

Threat models that only consider technical controls (encryption, auth) but ignore process controls (incident response, access reviews, training) miss half the picture. **Include operational and procedural threats.**

---

## 11. Further Reading

- **OWASP Threat Modeling Cheat Sheet** — practical quick-reference guide
- **Microsoft SDL Threat Modeling Tool** — documentation and tutorials on STRIDE
- **"Threat Modeling: Designing for Security"** by Adam Shostack — the definitive book on threat modeling
- **"Risk Centric Threat Modeling"** by Tony UcedaVélez & Marco M. Morana — deep dive on PASTA
- **LINDDUN Website** (linddun.org) — privacy threat modeling resources, case studies, and tools
- **CAPEC (Common Attack Pattern Enumeration and Classification)** — MITRE's catalog of attack patterns used in PASTA Stage 4

---

> **Key Takeaway:** Threat modeling is not about having a perfect threat list — it is about building the *habit* of asking "what could go wrong?" before building. A team that threat models poorly but consistently will outperform a team that does it perfectly once and never again. Start simple (STRIDE + DFD), iterate, and let the practice grow with your system.
