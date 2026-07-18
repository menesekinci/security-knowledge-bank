---
source: "languages/javascript/case-studies/event-stream-2018-npm-supply-chain.md"
title: "event-stream / flatmap-stream npm Supply Chain Attack (2018) — JavaScript/Node.js"
category: "case-study"
language: "javascript"
severity: "critical"
tags: [case-study, cause, happened, impact, javascript, root, system, target, what, when]
---

# event-stream / flatmap-stream npm Supply Chain Attack (2018) — JavaScript/Node.js

> **Severity:** Critical
> **Class:** Supply-chain compromise via social engineering + malicious transitive dependency
> **Disclosed:** November 20–26, 2018

---

## 📅 When Did It Happen?

The (then-benign) `flatmap-stream` dependency was added to `event-stream@3.3.6` on **September 9, 2018**; the actual malicious payload shipped later, in **`flatmap-stream@0.1.1` around October 5, 2018**. Publicly discovered around **November 20–26, 2018**.

## 🎯 Target System

`event-stream` — a popular Node.js stream utility averaging roughly **2 million downloads per week** on npm. The real target was **Copay** (a BitPay Bitcoin wallet) whose builds bundled the library.

## 🔴 What Happened?

A patient, socially-engineered supply-chain attack:

1. **Maintainer handover:** `event-stream`'s sole maintainer, Dominic Tarr, no longer used the package and handed publish rights to a new volunteer using the npm handle **`right9ctrl`**.
2. **Dependency added, then weaponized:** `right9ctrl` added **`flatmap-stream`** as a dependency of **`event-stream@3.3.6`** on **September 9, 2018** (still benign at that point), then published the malicious **`flatmap-stream@0.1.1`** — containing the encrypted payload — around **October 5, 2018**, which existing `event-stream@3.3.6` installs then pulled in transitively.
3. **Targeted payload:** the obfuscated code read the **`description` field of the host project's `package.json`** and used it as an **AES-256 key**. It only decrypted when that description was *"A Secure Bitcoin Wallet"* — i.e. inside **bitpay/copay** builds.
4. **Theft:** in Copay releases **5.0.2–5.1.0**, the decrypted payload harvested account details and **private keys from wallets holding more than 100 BTC or 1000 BCH**, exfiltrating them to an attacker server.
5. **Discovery:** a developer investigating an unrelated deprecation warning (via `nodemon`) noticed the suspicious dependency and raised the alarm.

## 🧠 Root Cause

1. **Maintainer burnout / trust transfer** — a single unpaid maintainer handed full publish rights to a stranger who had built up apparent goodwill.
2. **No review of transitive dependencies** — `flatmap-stream`'s content was never audited; consumers pulled it automatically.
3. **npm permission model** — full publishing control could be transferred in one step.
4. **Unpinned auto-updates** — anyone installing `event-stream@3.3.6` during the window silently pulled the malware.

## 💥 Impact

- ~2M weekly downloads; **~3,900 npm packages** depended (directly or transitively) on `event-stream`, including tooling like `nodemon`, `ps-tree`, and parts of many build pipelines.
- Copay Bitcoin/Bitcoin-Cash private keys were at risk; BitPay advised users on affected versions to **assume keys were compromised** and move funds.
- A watershed moment for npm supply-chain security awareness.
- Dominic Tarr was publicly criticized — largely unfairly, as an unpaid solo maintainer.

## 🛠️ How Was It Fixed / Contained?

- `flatmap-stream` was removed and the malicious `event-stream` version unpublished.
- Security scanners (Snyk et al.) added advisories.
- Copay shipped **5.2.0** and told affected users to create new wallets / move funds.
- npm strengthened its security processes and pushed **2FA** for maintainer accounts.

## 🤖 How AI / Vibe Coding Recreates This Class

AI assistants readily suggest `npm install <popular-package>` for a task ("use `event-stream` for streams") based on popularity, **without weighing supply-chain risk** — number of maintainers, recency, or history. An AI-recommended package can be perfectly fine today and compromised tomorrow, and AI will still recommend a **transitively** malicious tree. Treat every AI-suggested dependency as untrusted input.

## ✅ Prevention Checklist

- [ ] Commit and honor a **lockfile** (`package-lock.json` / `yarn.lock`); never blanket auto-update.
- [ ] Run **`npm audit`** / Snyk / OSV scanning in CI, including transitive deps.
- [ ] Pin versions and review **diffs of dependency updates**, not just your own code.
- [ ] Prefer packages with multiple active maintainers and 2FA-protected publishing.
- [ ] Isolate build/release environments; don't give build scripts access to secrets they don't need.
- [ ] Vet **AI-recommended packages** (maintainers, downloads, last publish, open issues) before installing.

## 🚩 Vibe-Coding Red Flags

- Adding a dependency solely because "it's the popular one" an AI named.
- No lockfile, or CI that silently upgrades transitive dependencies.
- Release builds that run arbitrary dependency code with access to signing keys / secrets.

## 🔗 Sources

- npm Blog — Details about the event-stream incident: https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident
- Snyk — A post-mortem of the malicious event-stream backdoor: https://snyk.io/blog/a-post-mortem-of-the-malicious-event-stream-backdoor/
- The Register (2m downloads/week): https://www.theregister.com/2018/11/26/npm_repo_bitcoin_stealer/
- es-incident — A Systematic Analysis of the Event-Stream Incident: https://es-incident.github.io/paper.html
