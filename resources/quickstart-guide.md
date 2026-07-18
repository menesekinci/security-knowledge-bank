# 🚀 Vibe Coding Security — Quick Start Guide

> Security steps you can apply in 5 minutes when starting a new project.

## Step 1: Provide the Right Prompt

Use this prompt at the START of every AI session:

```
⚠️ SECURITY INSTRUCTIONS:
1. Don't embed user input directly into SQL/command/template
2. Don't use eval/exec/system
3. Don't hardcode API keys
4. Validate all input
5. Check types during deserialization
6. Pin dependency versions
7. Don't log sensitive data
8. Don't expose stack traces in errors
```

## Step 2: Choose Your Language → Apply Its Checklist

```
knowledge-bank/languages/<language>/hardening-checklist.md
```

Pre-deployment checklist ready for every language.

## Step 3: Test the Code from AI

```bash
# Python
pip-audit && bandit -r src/

# JavaScript
npm audit && npx eslint --rulesdir security-rules

# Rust
cargo audit && cargo deny check

# Go
gosec ./... && go vet ./...

# Java
mvn dependency-check:check

# .NET
dotnet list package --vulnerable
```

## Step 4: Learn from Case Studies

Check the `case-studies/` folder for your project's language.
"If it happened to someone else, it can happen to you."

## Step 5: Update Regularly

```bash
# Weekly:
pip-audit / npm audit / cargo audit / go vet

# Before every deployment:
dependency vulnerability check
```
