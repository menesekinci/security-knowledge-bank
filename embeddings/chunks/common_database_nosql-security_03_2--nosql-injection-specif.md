---
source: "common/database/nosql-security.md"
title: "NoSQL Database Security for AI-Generated Applications"
heading: "2. NoSQL Injection Specific"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common-vuln, explanation, incidents, injection, nosql, prevention, real, vulnerability]
chunk: 3/8
---

## 2. NoSQL Injection Specific

### MongoDB `$where` Injection

MongoDB's `$where` operator passes a JavaScript string to be evaluated on the database server. AI-generated code often uses `$where` to perform "flexible" queries:

```javascript
// VULNERABLE - AI-generated $where injection
app.post('/search', (req, res) => {
  const username = req.body.username;
  db.collection('users').find({
    $where: `this.username == '${username}'`  // JavaScript injection!
  }).toArray((err, docs) => res.json(docs));
});
```

**Attack:**
```json
{"username": "' || true || '"}
```
Returns all users. An attacker can escalate to `' || sleep(5000) || '` for blind injection or `' || (function(){...})() || '` for arbitrary JavaScript execution.

### MongoDB `$gt` / `$ne` / `$regex` Bypass

Even without `$where`, MongoDB queries are vulnerable to operator injection when user input is passed directly:

```javascript
// VULNERABLE - AI-generated direct object injection
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.collection('users').findOne({
    username: username,   // Could be {"$gt": ""} or {"$ne": null}
    password: password    // Could be {"$gt": ""}
  }).then(user => { /* authentication bypassed */ });
});
```

**Attack:**
```json
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```
Logs in as the first user in the database — typically an admin.

### Elasticsearch Query DSL Injection

When user input is embedded in Elasticsearch query JSON:

```python
# VULNERABLE - AI-generated Elasticsearch query injection
@app.route('/search')
def search():
    q = request.args.get('q')
    body = {
        "query": {
            "query_string": {
                "query": q  # No sanitization!
            }
        }
    }
    return es.search(index="products", body=body)
```

**Attack:**
```
/search?q=malicious+field"+]},"match_all":{}}
```

An attacker can manipulate the query structure, bypass filters, access restricted fields, or cause denial of service via expensive queries.

### Elasticsearch Script Injection

When dynamic scripts are enabled:

```json
// Attack payload sent to _update endpoint
{
  "script": {
    "source": "ctx._source.amount = -1; ctx.op = 'none'",
    "lang": "painless"
  },
  "query": {
    "match": {
      "user": "victim"
    }
  }
}
```

---