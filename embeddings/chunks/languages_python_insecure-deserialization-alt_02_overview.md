---
source: "languages/python/insecure-deserialization-alt.md"
title: "Insecure Deserialization: Python Alternatives Compared"
heading: "Overview"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [cve-2020-14343, cve-2026-24009, jsonpickle, language-vuln, library, overview, pickle, python, pyyaml, security]
chunk: 2/10
---

## Overview

While `pickle` RCE is well-known, Python developers often switch to alternatives like **PyYAML**, **jsonpickle**, or **msgpack** believing they are safe. This is a dangerous misconception. Each serialization library has unique security properties, and none are safe for untrusted data without careful configuration.

This document provides a side-by-side security comparison of Python serialization formats.

---