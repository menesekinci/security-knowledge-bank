---
source: "common/api-security/graphql-security.md"
title: "GraphQL Security"
heading: "2. Query Depth & Complexity Limits"
category: "api-security"
language: "common"
severity: "medium"
tags: [api-security, attacks, batching, depth, introspection, leaks, overview, query, table]
chunk: 5/10
---

## 2. Query Depth & Complexity Limits

Without depth/ complexity limits, attackers can craft deeply nested queries that cause DoS:

```graphql
# MALICIOUS: Deeply nested query to exhaust server
query {
  user(id: 1) {
    posts { comments { user { posts { comments { user { name } } } } } }
    followers { posts { comments { user { posts { ... } } } } }
  }
}
```

### Vulnerable Code (No Depth Limit)

```javascript
// VULNERABLE: No depth or complexity limits
const server = new ApolloServer({ typeDefs, resolvers });
```

### Secure Code (Depth & Complexity Limits)

```javascript
// SECURE: Depth and complexity limits using graphql-query-complexity
const { createComplexityLimitRule } = require('graphql-validation-complexity');

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [
    // Limit query depth to 7 levels
    depthLimit(7),
    // Limit complexity score (e.g., each field costs 1, list fields cost more)
    createComplexityLimitRule(1000, {
      onCost: cost => console.log(`Query cost: ${cost}`),
      formatErrorMessage: cost => `Query too complex (${cost}). Max: 1000`
    })
  ]
});
```

---