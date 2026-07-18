---
source: "common/api-security/graphql-security.md"
title: "GraphQL Security"
heading: "3. Batching Attacks"
category: "api-security"
language: "common"
severity: "medium"
tags: [api-security, attacks, batching, depth, introspection, leaks, overview, query, table]
chunk: 6/10
---

## 3. Batching Attacks

GraphQL allows batching multiple queries in a single request. Attackers exploit this to:

- **Credential stuffing**: batch 100+ login mutations
- **Data scraping**: batch 50+ user queries with different IDs
- **Rate limit bypass**: single HTTP request escapes per-request limits

### Vulnerable Code (Unrestricted Batching)

```javascript
// VULNERABLE: Apollo Server accepts unlimited batched queries
// POST /graphql with body:
// [
//   { "query": "mutation { login(pass: \"test1\") { token } }" },
//   { "query": "mutation { login(pass: \"test2\") { token } }" },
//   ... 100+ more
// ]
```

### Secure Code (Limit Batching)

```javascript
// SECURE: Custom batching limits
const { ApolloServer } = require('@apollo/server');

const server = new ApolloServer({
  typeDefs,
  resolvers,
  plugins: [{
    async requestDidStart({ request }) {
      // Reject batch requests entirely for mutations
      if (Array.isArray(request.http?.body)) {
        const hasMutations = request.http.body.some(
          op => op.query?.trimStart().startsWith('mutation')
        );
        if (hasMutations) {
          throw new Error('Batch mutations not allowed');
        }
        if (request.http.body.length > 10) {
          throw new Error('Batch limit: max 10 operations');
        }
      }
    }
  }]
});
```

### Rate-Limiting per GraphQL Operation

```javascript
// SECURE: Rate limit per operation type
const rateLimit = require('graphql-rate-limit');

const resolvers = {
  Mutation: {
    login: rateLimit({
      window: '5m',
      max: 3,
      message: 'Too many login attempts',
      // Key by IP + operation
      keyGenerator: (context) => context.ip
    })(async (_, { email, password }) => {
      return authenticateUser(email, password);
    })
  }
};
```

---