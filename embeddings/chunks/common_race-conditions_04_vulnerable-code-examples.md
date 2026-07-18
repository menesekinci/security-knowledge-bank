---
source: "common/race-conditions.md"
title: "Race Conditions / TOCTOU (Time-of-Check Time-of-Use)"
heading: "Vulnerable Code Examples"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common, common-vuln, prevention, race, vibe, vulnerable, what]
chunk: 4/8
---

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