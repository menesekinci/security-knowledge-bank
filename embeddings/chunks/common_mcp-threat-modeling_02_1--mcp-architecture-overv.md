---
source: "common/mcp-threat-modeling.md"
title: "MCP Threat Modeling"
heading: "1. MCP Architecture Overview"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [architecture, categories, common-vuln, incident, mitigation, references, response, strategies, threat]
chunk: 2/6
---

## 1. MCP Architecture Overview

The Model Context Protocol (MCP) defines a client-server architecture for connecting AI agents to external tools and data sources. Understanding the data flow and trust boundaries is essential for threat modeling.

```
┌──────────────────────────────────────────────────────────────────┐
│                        TRUST BOUNDARY 1                         │
│                         (User Domain)                           │
│                                                                  │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────────┐  │
│  │  User / App   │────▶│  MCP Host    │────▶│  LLM / AI Agent │  │
│  │  Interface    │     │  (Client)    │     │  (Reasoning)     │  │
│  └──────────────┘     └──────────────┘     └────────┬─────────┘  │
│                                                      │            │
│                    Trust Boundary 2                  │            │
│  ┌───────────────────────────────────────────────────┘            │
│  │                                                                 │
│  ▼                                                                 │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    MCP Client Library                        │  │
│  │  (Session Management / Tool Discovery / Context Passing)    │  │
│  └──────────┬──────────────────────────────────┬────────────────┘  │
│             │                                  │                    │
│    ┌────────▼────────┐               ┌────────▼────────┐          │
│    │ TRUST BOUNDARY 3│               │ TRUST BOUNDARY 3│          │
│    │ (MCP Server A)  │               │ (MCP Server B)  │          │
│    │                 │               │                 │          │
│    │  Tools:         │               │  Tools:         │          │
│    │  - read_file    │               │  - send_email   │          │
│    │  - write_file   │   Context     │  - query_db     │          │
│    │  - search_code  │◄──Sharing────▶│  - call_api     │          │
│    │                 │               │                 │          │
│    │  Auth: OAuth2   │               │  Auth: Static   │          │
│    │  Sandbox: Yes   │               │  Sandbox: No    │          │
│    └────────┬────────┘               └────────┬────────┘          │
│             │                                  │                    │
│             ▼                                  ▼                    │
│    ┌──────────────────┐              ┌──────────────────┐         │
│    │ External Systems │              │ External Systems │         │
│    │ (Files, APIs)    │              │ (Email, DBs)     │         │
│    └──────────────────┘              └──────────────────┘         │
└──────────────────────────────────────────────────────────────────┘
```

### Trust Boundaries

| Boundary | Description | Risk Level |
|----------|-------------|------------|
| **TB1** | User ↔ MCP Host (User Interface) | Medium — user input may contain injection payloads |
| **TB2** | MCP Host ↔ MCP Client Library | Low — in-process, but session IDs may be guessable |
| **TB3** | MCP Client ↔ MCP Server(s) | **Critical** — the primary attack surface; multiple servers share context |
| **TB4** | MCP Server ↔ External Services | High — servers interact with filesystems, APIs, databases |

### Data Flow (Normal Operation)

1. **User Input:** User submits a prompt to the application
2. **Intent Parsing:** LLM interprets the prompt and identifies required tools
3. **Tool Discovery:** MCP Client queries connected servers for available tools (name + description + schema)
4. **Tool Selection:** LLM selects a tool based on its description (this is where **tool poisoning** occurs)
5. **Tool Invocation:** MCP Client sends arguments to the server
6. **Execution:** Server executes the tool and returns output
7. **Context Injection:** Tool output enters the LLM's context window (this is where **prompt injection** via tool output occurs)
8. **Cross-Server Cascade:** Output from Server A can influence calls to Server B

---