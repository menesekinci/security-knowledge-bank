# Business Logic Vulnerabilities

**CWE:** CWE-840 (Business Logic Errors), CWE-841 (Improper Enforcement of Behavioral Workflow)
**OWASP Top 10:2021:** A04 — Insecure Design

---

## What Are Business Logic Vulnerabilities?

Business logic flaws are **design-level vulnerabilities** where attackers abuse the intended functionality of an application to gain unauthorized benefits. Unlike technical vulnerabilities (SQLi, XSS), these don't involve injection or bypassing controls — the attacker simply uses the application in a way the developers didn't anticipate.

**Examples:** Applying the same discount code 100 times, buying a $1000 item for $10 by manipulating quantity, skipping payment step, resetting another user's password.

## Why Vibe Coding Makes This Worse

- **AI doesn't understand business context:** AI writes code for "apply coupon" but doesn't implement "apply coupon once per user"
- **AI assumes honest users:** Generated workflows don't anticipate adversarial behavior
- **AI generates linear happy paths:** "Step 1 → Step 2 → Step 3" but doesn't enforce ordering
- **AI uses client-side trust:** AI puts business rules in JavaScript that runs on the user's browser
- **No rate limiting on business actions:** AI forgets to limit coupon redemptions, balance checks, etc.

## Common Business Logic Flaws

### 1. Discount/Coupon Abuse

**Vulnerable Code (Node.js)**
```javascript
app.post('/apply-coupon', async (req, res) => {
    const { code } = req.body;
    // 🔴 VULNERABLE: no per-user limit
    const coupon = await db.coupons.findOne({ code, active: true });
    if (!coupon) return res.status(400).send('Invalid coupon');
    // Attacker can apply this coupon to EVERY order!
    req.session.discount = coupon.discount;
    res.send(`Coupon applied! ${coupon.discount}% off`);
});
```

**Fixed Code**
```javascript
app.post('/apply-coupon', async (req, res) => {
    const { code } = req.body;

    // ✅ Check coupon exists and is active
    const coupon = await db.coupons.findOne({
        code,
        active: true,
        expiresAt: { $gt: new Date() }
    });
    if (!coupon) return res.status(400).send('Invalid coupon');

    // ✅ Check per-user usage limit
    const usageCount = await db.coupon_usage.countDocuments({
        couponId: coupon.id,
        userId: req.userId
    });
    if (usageCount >= coupon.maxUsesPerUser) {
        return res.status(400).send('Coupon already used');
    }

    // ✅ Record usage atomically
    await db.coupon_usage.create({
        couponId: coupon.id,
        userId: req.userId,
        orderId: req.session.orderId
    });

    req.session.discount = coupon.discount;
    res.send(`Coupon applied! ${coupon.discount}% off`);
});
```

### 2. Price Manipulation

**Vulnerable Code**
```python
@app.route('/add-to-cart', methods=['POST'])
def add_to_cart():
    # 🔴 VULNERABLE: trust client-supplied price
    item_id = request.json['item_id']
    price = request.json.get('price')  # Client sends the price!
    quantity = request.json.get('quantity', 1)

    cart.add(item_id, price, quantity)
    return 'Added to cart'
# Attack: Set price to $0.01 for a $1000 item
```

**Fixed Code**
```python
@app.route('/add-to-cart', methods=['POST'])
def add_to_cart():
    item_id = request.json['item_id']
    quantity = request.json.get('quantity', 1)

    # ✅ Always get price from server/database
    item = db.execute("SELECT price FROM items WHERE id = ?", (item_id,))
    if not item:
        return 'Item not found', 404
    price = item.price

    # ✅ Validate quantity
    if quantity < 1 or quantity > item.max_per_order:
        return 'Invalid quantity', 400

    cart.add(item_id, price, quantity)
    return 'Added to cart'
```

### 3. Step Skipping (Workflow Bypass)

**Vulnerable Code**
```javascript
// 🔴 VULNERABLE: no workflow state enforcement
app.get('/checkout/payment', async (req, res) => {
    res.render('payment');
});

app.get('/checkout/confirmation', async (req, res) => {
    // User can navigate directly to /confirmation without paying!
    const order = await db.orders.findById(req.session.orderId);
    res.render('confirmation', { order });
});
```

**Fixed Code**
```javascript
// ✅ Enforce workflow state
const WORKFLOW = ['cart', 'shipping', 'payment', 'confirmation'];

app.get('/checkout/*', async (req, res) => {
    const currentStep = req.path.split('/')[2];
    const order = await db.orders.findById(req.session.orderId);

    // Check the user completed the previous step
    const currentIdx = WORKFLOW.indexOf(currentStep);
    if (currentIdx > 0) {
        const prevStep = WORKFLOW[currentIdx - 1];
        if (!order.completedSteps.includes(prevStep)) {
            return res.redirect(`/checkout/${prevStep}`);
        }
    }

    // For payment: validate amount wasn't tampered with
    if (currentStep === 'payment') {
        const expectedTotal = calculateTotal(order.items);
        if (order.total !== expectedTotal) {
            return res.status(400).send('Order total mismatch');
        }
    }
});
```

### 4. Rate Limit Bypass on Business Operations

**Vulnerable Code**
```javascript
// 🔴 VULNERABLE: no rate limiting on money-critical operations
app.post('/create-account', async (req, res) => {
    const { referralCode } = req.body;
    // Referral bonus: $10 for each new account
    const user = await createUser(req.body);

    if (referralCode) {
        await addReferralBonus(referralCode, 10);  // +$10
    }
    res.send('Account created');
});
// Attacker: Creates 10,000 accounts → $100,000 in referral bonuses
```

**Fixed Code**
```javascript
// ✅ Rate limit account creation
const signupLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,  // 1 hour
    max: 3,                     // 3 accounts per hour per IP
    keyGenerator: (req) => req.ip
});

app.post('/create-account', signupLimiter, async (req, res) => {
    const { referralCode, phone, email } = req.body;

    // ✅ Require verified phone/email for referral bonus
    if (!req.session.phoneVerified) {
        return res.status(400).send('Verify phone first');
    }

    // ✅ Check referral code not recently used by similar device/IP
    const recentUsage = await db.referral_usage.countDocuments({
        referralCode,
        createdAt: { $gt: Date.now() - 24 * 60 * 60 * 1000 },
        ip: req.ip
    });
    if (recentUsage > 0) {
        return res.status(400).send('Referral already used from this device');
    }

    const user = await createUser(req.body);
    if (referralCode) {
        await addReferralBonus(referralCode, 10);
    }
    res.send('Account created');
});
```

---

## Detection Strategies

| Technique | What to Look For |
|---|---|
| Workflow fuzzing | Try steps out of order, skip steps, repeat steps |
| Parameter tampering | Change prices, quantities, discount values in requests |
| Race conditions | Send parallel requests for coupon redemptions, transfers |
| State manipulation | Modify cookies, tokens to change workflow state |
| Integer overflow | MAX_INT + 1 = negative (free money!) |
| Negative values | Negative quantity → negative price (store pays you) |

---

## Prevention Checklist for AI Prompts

```
✅ BUSINESS LOGIC REQUIREMENTS:
- Never trust client-side values for prices, discounts, or quantities
- Validate every business operation against server-side state
- Enforce workflow ordering — don't allow step skipping
- Implement per-user rate limiting on all business operations
- Add usage limits for discounts, referral codes, and promotions
- Use idempotency keys to prevent duplicate operations
- Log all business operations for audit trail
- Add fraud detection: flag unusual patterns (many accounts from same IP)
- Validate that quantities are positive and within sensible ranges
- Enforce minimum/maximum order values server-side
```

---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Smart Coupons for WooCommerce (< 2.3.0) — coupon abuse | CVE-2026-45438 | Missing Authorization (CWE-862): unauthenticated users mint high-value coupons — CVSS 7.5 (v3.1) |
| WooCommerce PayPal Payments (≤ 4.0.1) — payment-flow bypass | CVE-2026-9284 | Missing Authorization (CWE-862): unauthenticated order manipulation / mark order paid without a real PayPal capture — CVSS 8.2 (v3.1) |
| Starbucks gift cards — race-condition double-spend | N/A (no CVE — bug bounty) | Concurrent balance transfers duplicate funds, creating money from nothing (E. Homakov, 2015) |
| Stripe promotion code — redemption-limit bypass | N/A (no CVE — bug bounty) | Race condition lets a single-use promo code be redeemed past its limit (HackerOne #1717650) |
| Instacart — coupon redemption race condition | N/A (no CVE — bug bounty) | Parallel requests stack the same coupon for near-unlimited discount (HackerOne #157996) |

---

## References

- [OWASP A04:2021 — Insecure Design](https://owasp.org/Top10/2021/A04_2021-Insecure_Design/)
- [OWASP Business Logic Vulnerabilities](https://owasp.org/www-community/vulnerabilities/Business_Logic_Vulnerability)
- [PortSwigger — Business Logic Vulnerabilities](https://portswigger.net/web-security/logic-flaws)
