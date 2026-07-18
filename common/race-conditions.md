# Race Conditions / TOCTOU (Time-of-Check Time-of-Use)

**CWE:** CWE-362 (Concurrent Execution with Shared Resource), CWE-367 (TOCTOU Race Condition)
**OWASP Top 10:2021:** A01 — Broken Access Control (race conditions in concurrent operations)

---

## What Are Race Conditions?

A race condition occurs when **multiple threads or processes access shared resources** simultaneously without proper synchronization. The timing of operations matters — an attacker can **win the race** by exploiting the gap between a security check and the actual operation (TOCTOU).

**Simple explanation:** Checking if a user has enough money, then deducting — but if two requests do the check before either does the deduct, both succeed. The user gets double the money.

## Why Vibe Coding Makes This Worse

- **AI writes synchronous-looking async code:** `async/await` patterns that look correct but have hidden race windows
- **AI doesn't use transactions:** Generated code does separate read+write operations (check balance → deduct) without wrapping in a transaction
- **AI misses database-level locking:** `SELECT ... FOR UPDATE` is obscure and AI rarely generates it
- **AI uses "if exists then create" pattern:** Checking existence before inserting without unique constraints
- **AI generates file-based temp files:** Check if file exists → read file → another process modifies it in between

## Vulnerable Code Examples

### Banking: Insufficient Funds Check

**Python — Vulnerable**
```python
@app.route('/transfer', methods=['POST'])
def transfer():
    sender_id = session['user_id']
    amount = request.json['amount']
    recipient_id = request.json['recipient']

    # 🔴 RACE CONDITION: Two concurrent requests both check balance
    sender = db.execute("SELECT balance FROM accounts WHERE id = ?", (sender_id,))
    if sender.balance < amount:
        return 'Insufficient funds', 400

    # Both requests pass the check before either deducts!
    db.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", (amount, sender_id))
    db.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", (amount, recipient_id))
    return 'Success'
```

**Fixed — Use Transaction with Lock**
```python
@app.route('/transfer', methods=['POST'])
def transfer():
    sender_id = session['user_id']
    amount = request.json['amount']
    recipient_id = request.json['recipient']

    # ✅ Use database transaction with row-level lock
    conn = get_db()
    # SQLite has no SELECT ... FOR UPDATE; BEGIN IMMEDIATE takes a write lock
    # up front so no other writer can interleave between the check and the update.
    conn.execute("BEGIN IMMEDIATE TRANSACTION")
    try:
        sender = conn.execute(
            "SELECT balance FROM accounts WHERE id = ?",
            (sender_id,)
        ).fetchone()

        if sender.balance < amount:
            conn.execute("ROLLBACK")
            return 'Insufficient funds', 400

        conn.execute(
            "UPDATE accounts SET balance = balance - ? WHERE id = ?",
            (amount, sender_id)
        )
        conn.execute(
            "UPDATE accounts SET balance = balance + ? WHERE id = ?",
            (amount, recipient_id)
        )
        conn.execute("COMMIT")
        return 'Success'
    except Exception as e:
        conn.execute("ROLLBACK")
        raise
```

### Node.js: Coupon Redemption

**Node.js — Vulnerable**
```javascript
app.post('/redeem-coupon', async (req, res) => {
    const { code } = req.body;

    // 🔴 RACE: two requests both check the coupon at the same time
    const coupon = await db.coupons.findOne({ code, used: false });

    if (!coupon) return res.status(400).send('Invalid or used');

    // Both requests see used:false and proceed
    await db.coupons.updateOne({ code }, { used: true });
    await db.users.updateOne({ _id: req.userId }, { $inc: { balance: coupon.value } });

    res.send('Coupon redeemed!');
});
```

**Fixed — Use Atomic Operation**
```javascript
app.post('/redeem-coupon', async (req, res) => {
    const { code } = req.body;

    // ✅ Atomic find-and-update — only one request succeeds
    const result = await db.coupons.findOneAndUpdate(
        { code, used: false },           // Find unused coupon
        { $set: { used: true, usedBy: req.userId, usedAt: new Date() } },
        { returnDocument: 'before' }     // Returns original doc
    );

    // result is null if no matching coupon was found (already used)
    if (!result) {
        return res.status(400).send('Invalid or already used');
    }

    await db.users.updateOne(
        { _id: req.userId },
        { $inc: { balance: result.value } }
    );

    res.send('Coupon redeemed!');
});
```

### Java: TOCTOU File Access

**Java — Vulnerable**
```java
// 🔴 TOCTOU: check exists, then read — file could change between
public String readFile(String filename) throws Exception {
    File file = new File("/app/data/" + filename);
    if (!file.exists() || !file.isFile()) {
        throw new SecurityException("Access denied");
    }
    // In between, attacker replaces file with symlink to /etc/passwd
    return Files.readString(file.toPath());  // Reads wrong file!
}
```

**Java — Fixed**
```java
public String readFile(String filename) throws Exception {
    // ✅ Open the file in one atomic operation
    Path baseDir = Paths.get("/app/data").toRealPath();
    Path filePath = baseDir.resolve(filename).normalize();

    if (!filePath.startsWith(baseDir)) {
        throw new SecurityException("Access denied");
    }

    // ✅ Atomic read — no TOCTOU window
    try (FileChannel channel = FileChannel.open(filePath, StandardOpenOption.READ)) {
        // Check size after opening
        if (channel.size() > MAX_FILE_SIZE) {
            throw new SecurityException("File too large");
        }
        return Files.readString(filePath);
    }
}
```

---

## Common Race Condition Patterns

| Pattern | Danger | Fix |
|---|---|---|
| Check-then-act | Two requests pass the check before either acts | Atomic operations (CAS, findAndModify) |
| Lazy initialization | Two threads initialize singleton simultaneously | Double-checked locking, synchronized |
| Read-compare-write | Read value, compare, write new value | Optimistic locking with version numbers |
| File TOCTOU | Check file state, then use it | Open file first, then verify |
| Non-atomic increment | `counter += 1` is read-modify-write | `UPDATE ... SET counter = counter + 1` |
| Async race | Two promises both resolve to modify shared state | Mutex, queue, or atomic operations |

---

## Prevention Checklist for AI Prompts

```
✅ RACE CONDITION PREVENTION:
- Use database transactions for multi-step operations
- Use atomic update operations (findOneAndUpdate, UPDATE ... WHERE condition)
- Use row-level locks (SELECT ... FOR UPDATE)
- Add unique constraints to prevent duplicate operations
- For file operations: open the file, then verify, not the reverse
- Use optimistic locking with version numbers (increment on update)
- Avoid shared mutable state in async code
- Use message queues for serializing access to critical resources
- Test concurrent access with stress testing tools
```

---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Linux kernel copy-on-write race (Dirty COW) | CVE-2016-5195 | Local privilege escalation via COW race in `mm/gup.c` |
| Apple iOS kernel race | CVE-2021-1782 | Local privilege escalation |
| Docker container escape | CVE-2019-14271 | TOCTOU in `docker cp` → host access |
| Linux kernel race (Dirty Pipe) | CVE-2022-0847 | Privilege escalation via pipe race |
| OpenSSH signal-handler race (regreSSHion) | CVE-2024-6387 | Unauthenticated RCE as root via SIGALRM race in sshd |

---

## References

- [OWASP Race Condition](https://owasp.org/www-community/vulnerabilities/Race_Condition)
- [CWE-362: Concurrent Execution with Shared Resource](https://cwe.mitre.org/data/definitions/362.html)
- [CWE-367: TOCTOU Race Condition](https://cwe.mitre.org/data/definitions/367.html)
