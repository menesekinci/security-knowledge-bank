---
source: "common/api-security/graphql-security.md"
title: "GraphQL Security"
heading: "4. N+1 Problem & Data Leakage"
category: "api-security"
language: "common"
severity: "medium"
tags: [api-security, attacks, batching, depth, introspection, leaks, overview, query, table]
chunk: 7/10
---

## 4. N+1 Problem & Data Leakage

The N+1 problem in GraphQL — resolvers making one database call per parent result — can be weaponized:

- **Performance DoS**: Force dozens of SQL queries per request
- **Information disclosure**: Timing side-channels across batched requests
- **Authorization bypass**: Each resolver may independently check auth; deep queries skip checks

### Vulnerable Code (N+1 Pattern)

```javascript
// VULNERABLE: N+1 queries — each post triggers its own DB call
const resolvers = {
  User: {
    posts: (parent, args, context) => {
      // Called once per user — N+1 problem!
      return db.query('SELECT * FROM posts WHERE author_id = ?', [parent.id]);
    }
  }
};
```

### Secure Code (DataLoader Batching)

```javascript
// SECURE: DataLoader batch + caching
const DataLoader = require('dataloader');

const createLoaders = () => ({
  postsByUser: new DataLoader(async (userIds) => {
    const posts = await db.query(
      'SELECT * FROM posts WHERE author_id IN (?) ORDER BY author_id',
      [userIds]
    );
    // Group by user_id for DataLoader
    return userIds.map(id => posts.filter(p => p.author_id === id));
  }),
});

const resolvers = {
  User: {
    posts: (parent, args, context) => {
      // Single batched query for all users
      return context.loaders.postsByUser.load(parent.id);
    }
  }
};
```

---