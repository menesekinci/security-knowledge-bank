---
source: "common/business-logic.md"
title: "Business Logic Vulnerabilities"
heading: "Common Business Logic Flaws"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [business, checklist, common, common-vuln, detection, prevention, strategies, vibe, what]
chunk: 4/8
---

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