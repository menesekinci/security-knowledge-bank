---
source: "common/mcp-threat-modeling.md"
title: "MCP Threat Modeling"
heading: "4. Incident Response for MCP Compromise"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [architecture, categories, common-vuln, incident, mitigation, references, response, strategies, threat]
chunk: 5/6
---

## 4. Incident Response for MCP Compromise

### Phase 1: Triage (0–30 minutes)

1. **Isolate the compromised server:** Disconnect the MCP server from the agent
2. **Preserve context:** Capture the agent's context window (contains the poisoned input/output)
3. **Block outbound:** If RCE is suspected (CVE-2025-6514 style), block the host's network egress
4. **Identify blast radius:** List all MCP servers that shared context with the compromised server (72.4% cascade rate)
5. **Rotate credentials:** Rotate all secrets that were in the agent's context window

### Phase 2: Analysis (1–4 hours)

1. **Extract tool descriptions:** Pull the full tool metadata from the compromised server
2. **Scan for hidden instructions:** Look for HTML tags, base64, encoded payloads in descriptions
3. **Review invocation logs:** Reconstruct the sequence of tool calls before/during/after compromise
4. **Check for exfiltration:** Review network logs for outbound data transfers matching context content
5. **Identify attack vector:** Was it tool poisoning (T1), prompt injection (T2), supply chain (T5), or credential harvest (T4)?

### Phase 3: Remediation (4–24 hours)

1. **Patch/remove affected servers:** Apply fixes (e.g., mcp-remote v0.1.16 for CVE-2025-6514)
2. **Update security controls:** Enable description scanning, enforce sandboxing, implement OAuth
3. **Revoke and reissue credentials:** For any identity exposed during the incident
4. **Deploy behavioral monitoring:** Baseline normal tool call patterns for anomaly detection
5. **Notify affected parties:** If data was exfiltrated, follow breach notification requirements

### Phase 4: Post-Mortem (1–5 days)

1. **Update threat model:** Incorporate new attack vectors discovered
2. **Add detection rules:** Create SIEM rules for the specific attack pattern
3. **Update AIBOM:** Ensure all MCP servers are cataloged with provenance

---