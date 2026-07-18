# 💎 Ruby Security Hardening Checklist

> Items to check in every Ruby project before deployment.

## ✅ General
- [ ] Is `bundle audit` run?
- [ ] Is gem version pinned? (Is there a `Gemfile.lock`?)
- [ ] Is `bundler-audit` integrated into CI?

## ✅ Code Security
- [ ] Is `YAML.load()` not used? (Is `YAML.safe_load()` used?)
- [ ] Is `eval()`, `send()`, `class_eval()` security-checked?
- [ ] Is the string form of `system()`, `` ` ``, `%x()`, `exec()` not used?
- [ ] Is `Open3.capture3()` array form used?
- [ ] Is there mass assignment protection? (strong parameters)

## ✅ Rails Specific
- [ ] Is `params.permit` used correctly?
- [ ] Is `attr_accessible (Rails 3-4; removed in Rails 5+ — legacy only)` / `attr_protected (Rails 3-4; removed in Rails 5+ — legacy only)` not used?
- [ ] Is N+1 query checked? (DoS)
- [ ] Is session secret strong?

## ✅ Database
- [ ] Are ActiveRecord queries parameterized?
- [ ] Is `where("?")` placeholder used? (no string interpolation)
- [ ] If `find_by_sql` is used, is it sanitized?

## 🛡️ Vibe Coding Extra
- [ ] Was AI's `YAML.load()` suggestion replaced with `safe_load`?
- [ ] Was AI's backtick usage replaced with `Open3` array form?
- [ ] Is AI's mass assignment code protected with strong parameters?
