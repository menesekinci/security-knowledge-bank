---
source: "common/cloud-security/docker-security.md"
title: "Docker Security"
heading: "Overview"
category: "cloud-security"
language: "common"
severity: "medium"
tags: [cloud-security, containers, contexts, host, mounts, overview, privileged, security, table]
chunk: 2/11
---

## Overview

Docker containers share the host kernel, making container isolation critical. This document covers privileged containers, host mounts, security contexts, image scanning, rootless mode, and container escape vulnerabilities with CVE-backed examples.

---