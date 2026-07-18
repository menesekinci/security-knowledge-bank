# 🟡 Test Fatigue / Coverage Gaps (Test Blindness)

## What Is It?

AI produces code quickly, but writing tests feels "boring." Developers tell AI
"just write the code, I'll handle the tests" but then don't write tests.
Or the tests AI writes **pass but aren't meaningful**.

## How Does It Manifest in Vibe Coding?

### Scenario 1: No Tests
```
Developer: "AI wrote me 500 lines of production code, awesome!"
Developer: "Tests? Let me have AI write them... AI wrote 3 tests, they pass, merging"
Test coverage: %12 💀
```

### Scenario 2: Meaningless Test
```python
# AI-written test:
def test_login():
    result = login("user", "pass")
    assert result is not None  # 💀 What does "not None" test?
    # Password hash verification? Brute force protection? Rate limit? Session?
```

### Scenario 3: Happy Path Only
```python
# All 5 of the AI-written tests are happy path:
def test_search_found(): ...
def test_search_empty(): ...
def test_search_pagination(): ...
# NONE test edge cases:
# - SQL injection input → won't it crash?
# - Special characters / Unicode → will it error?
# - Rate limit → does it work?
```

## Prevention

### ✅ Statements to Add to Prompts
```
"When writing tests for code:
1. Test edge cases: empty input, null, SQL injection payload, XSS payload
2. Test negative scenarios: incorrect login, invalid token, unauthorized access
3. Add security tests: test every input validation
4. Consider mutation testing: do the AI-written tests actually catch errors?"
```

### 🔧 Practical Measures
1. **Coverage gate**: Don't allow merging below 80%
2. **Test review**: Also review the tests AI writes
3. **Fuzzing**: Add fuzz testing to security-critical functions
4. **Question AI's tests**: Ask "What does this test prove?"

## 🔗 Related Vulnerabilities
- [Overreliance](overreliance.md)
- [Business Logic Flaws (Common)](../common/business-logic.md)

---

**Severity: 🟡 Medium** — Not a security vulnerability on its own, but it prevents vulnerabilities from being caught.
