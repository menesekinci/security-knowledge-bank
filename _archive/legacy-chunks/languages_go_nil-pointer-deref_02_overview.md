---
source: "languages/go/nil-pointer-deref.md"
title: "Nil Pointer Dereference and Panic Recovery"
category: "language-vuln"
language: "go"
chunk: 2
total_chunks: 10
heading: "Overview"
---

## Overview

Go has pointers, but unlike C, nil pointer dereferences cause a **controlled panic** (not undefined behavior). The program crashes cleanly — which is better than memory corruption, but still a **denial of service** vulnerability. In production web servers, a nil pointer dereference can crash the entire process.

AI-generated Go code is especially prone to nil pointer bugs because:
1. LLMs forget to check error returns before using values
2. LLMs assume functions always return valid pointers
3. LLMs use `recover()` in incorrect patterns that mask bugs