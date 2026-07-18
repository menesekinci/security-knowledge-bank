---
source: "languages/javascript/npm-supply-chain.md"
title: "npm Supply Chain Security"
category: "language-vuln"
language: "javascript"
chunk: 6
total_chunks: 8
heading: "Prevention Checklist"
---

## Prevention Checklist

- [ ] ALWAYS pin exact versions in `dependencies` and `devDependencies` (no `^` or `~`)
- [ ] ALWAYS commit `package-lock.json` or `yarn.lock` to version control
- [ ] Use `npm ci` (clean install) in CI/CD instead of `npm install`
- [ ] Run `npm audit` in CI with `--audit-level=high`
- [ ] Review all `scripts` in AI-generated `package.json` for suspicious lifecycle hooks
- [ ] Use `.npmrc` with `save-exact=true` and `package-lock=true`
- [ ] Verify every package name AI generates — catch typo-squatting before first install
- [ ] Use private registries for internal packages with scoped names
- [ ] Never `npm install` at runtime in production
- [ ] Use `Socket.dev`, `Snyk`, or `GitHub Dependabot` for proactive monitoring
- [ ] Enable 2FA on npm accounts for package publishing
- [ ] Review transitive dependencies with `npm ls --depth=5` before major updates

---