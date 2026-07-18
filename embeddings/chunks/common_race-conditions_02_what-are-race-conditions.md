---
source: "common/race-conditions.md"
title: "Race Conditions / TOCTOU (Time-of-Check Time-of-Use)"
heading: "What Are Race Conditions?"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common, common-vuln, prevention, race, vibe, vulnerable, what]
chunk: 2/8
---

## What Are Race Conditions?

A race condition occurs when **multiple threads or processes access shared resources** simultaneously without proper synchronization. The timing of operations matters — an attacker can **win the race** by exploiting the gap between a security check and the actual operation (TOCTOU).

**Simple explanation:** Checking if a user has enough money, then deducting — but if two requests do the check before either does the deduct, both succeed. The user gets double the money.