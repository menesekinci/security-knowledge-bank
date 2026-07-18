---
source: "common/api-security/graphql-security.md"
title: "GraphQL Security"
heading: "1. Introspection Leaks"
category: "api-security"
language: "common"
severity: "medium"
tags: [api-security, attacks, batching, depth, introspection, leaks, overview, query, table]
chunk: 4/10
---

## 1. Introspection Leaks

GraphQL introspection allows clients to query the schema — types, fields, mutations, and subscriptions. If left enabled in production, it exposes the entire API surface to attackers.

> **Research finding:** According to Imperva, 50% of GraphQL endpoints were targeted with introspection attacks.

### Vulnerable Code (Introspection Enabled)

```javascript
// VULNERABLE: Apollo Server with introspection in production
const { ApolloServer } = require('@apollo/server');

const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true  // Enabled in production!
});
```

### Secure Code (Disable in Production)

```javascript
// SECURE: Conditionally disable introspection in production
const { ApolloServer } = require('@apollo/server');

const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',
  // Or use a custom plugin for fine-grained control:
  plugins: [{
    async requestDidStart({ request }) {
      if (request.operationName === 'IntrospectionQuery' && 
          process.env.NODE_ENV === 'production') {
        throw new Error('Introspection disabled in production');
      }
    }
  }]
});
```

---