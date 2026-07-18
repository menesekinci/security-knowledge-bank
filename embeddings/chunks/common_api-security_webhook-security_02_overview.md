---
source: "common/api-security/webhook-security.md"
title: "Webhook Security"
heading: "Overview"
category: "api-security"
language: "common"
severity: "medium"
tags: [api-security, attacks, bombing, overview, replay, retry, signature, table, verification]
chunk: 2/9
---

## Overview

Webhooks are HTTP callbacks that enable real-time event-driven communication between services. Because webhooks typically carry sensitive payloads and operate server-to-server without interactive authentication, they are frequent targets for signature verification bypass, replay attacks, retry bombing, and secret compromise.

---