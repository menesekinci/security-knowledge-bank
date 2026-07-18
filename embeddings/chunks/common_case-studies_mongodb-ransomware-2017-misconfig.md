---
source: "common/case-studies/mongodb-ransomware-2017-misconfig.md"
title: "MongoDB Ransomware (2017) — NoSQL Injection & Misconfiguration"
category: "case-study"
language: "common"
severity: "critical"
tags: [case-study, cause, happened, impact, root, system, target, what, when]
---

# MongoDB Ransomware (2017) — NoSQL Injection & Misconfiguration

## 📅 When Did It Happen?
January 2017

## 🎯 Target System
MongoDB databases — **tens of thousands (~28,000+)** MongoDB servers exposed to the internet without passwords

## 🔴 What Happened?
Hackers scanned servers running MongoDB with default configuration (no password, accessible from the internet). Of roughly 50,000 internet-facing MongoDB instances, **tens of thousands (~28,000+)** were ransacked.
- Deleted all databases and left a "ransom" note
- Demanded payment in Bitcoin
- Most victims lost their data because they hadn't made backups

## 🧠 Root Cause
```python
# VULNERABLE — As AI might write it:
client = MongoClient("mongodb://localhost:27017")  # No Authentication!
db = client["production"]
collection = db["users"]

# ... everything open without authentication ...
```

OR more dangerously — NoSQL injection:
```javascript
// Express.js + MongoDB:
app.post('/login', async (req, res) => {
    // 🚨 NoSQL Injection!
    const user = await db.collection('users').findOne({
        username: req.body.username,  // if { "$gt": "" } is sent...
        password: req.body.password   // returns all users!
    });
    
    if (user) {
        // Login successful! 💀
    }
});
```

## 💥 Impact
- Tens of thousands (~28,000+) MongoDB servers wiped
- Estimated millions of dollars in losses
- MongoDB security awareness exploded
- Default config changed with MongoDB 3.6+ (password required)

## 🎓 Lessons Learned
- **Never use default config** — authentication + authorization required
- **Network binding**: Listen only on internal IP (`127.0.0.1`)
- **NoSQL injection** is as dangerous as SQL injection
- **Input validation** at every input point
- Without **backup** you have to pay the ransom

## Vibe Coding Connection
When generating code with AI:
- AI skips authentication for "quick prototyping"
- Writes directly in the MongoDB connection string, doesn't use env variables
- Generally doesn't know NoSQL injection (focuses on SQL)

## 🔗 Source
- https://www.bleepingcomputer.com/news/security/mongodb-ransomware-attacks/
- https://www.troyhunt.com/the-dangers-of-default-configurations/
