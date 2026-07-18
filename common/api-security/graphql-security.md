# GraphQL Security

> **Category:** Common / API Security
> **Last Updated:** July 2026

## Overview

GraphQL APIs present unique security challenges compared to REST. The single-endpoint nature, introspection capabilities, and flexible query structure introduce distinct attack vectors. This document covers introspection leaks, query depth limits, batching attacks, N+1 problems, and authentication in resolvers, with CVE-backed examples.

---

## Table of Contents

1. [Introspection Leaks](#1-introspection-leaks)
2. [Query Depth & Complexity Limits](#2-query-depth--complexity-limits)
3. [Batching Attacks](#3-batching-attacks)
4. [N+1 Problem & Data Leakage](#4-n1-problem--data-leakage)
5. [Authentication & Authorization in Resolvers](#5-authentication--authorization-in-resolvers)
6. [CVEs & Real-World Examples](#6-cves--real-world-examples)

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

## 5. Authentication & Authorization in Resolvers

Common flaws:

- **Missing auth check** in some resolvers
- **Field-level authorization gaps** — querying fields with different sensitivity
- **Resolver-level bypass** — attacker constructs custom query skipping authorized paths

### Vulnerable Code (Auth in Router, Not Resolver)

```javascript
// VULNERABLE: Auth check only at HTTP middleware level
// The GraphQL single-endpoint bypasses route-level auth
app.use('/graphql', authMiddleware); // Only checks token presence

const resolvers = {
  Query: {
    adminDashboard: () => {
      // No auth check! If middleware didn't catch it...
      return db.query('SELECT * FROM admin_secrets');
    }
  }
};
```

### Secure Code (Auth in Every Resolver)

```javascript
// SECURE: Authorization in every sensitive resolver
const { ApolloServer } = require('@apollo/server');

// Centralized auth check utility
function requireRole(role) {
  return (next) => async (parent, args, context, info) => {
    if (!context.user) {
      throw new Error('Authentication required');
    }
    if (!context.user.roles.includes(role)) {
      throw new Error(`Role ${role} required`);
    }
    return next(parent, args, context, info);
  };
}

const resolvers = {
  Query: {
    sensitiveData: requireRole('admin')(async (_, args, context) => {
      return db.query('SELECT * FROM sensitive_data');
    }),
    userProfile: async (_, { id }, context) => {
      // Object-level authorization
      if (context.user.id !== id && !context.user.roles.includes('admin')) {
        throw new Error('Not authorized to view this profile');
      }
      return getUserById(id);
    }
  }
};

// Server with context always populated
const server = new ApolloServer({
  typeDefs,
  resolvers,
  context: async ({ req }) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return { user: null };
    try {
      const user = await verifyToken(token);
      return { user };
    } catch {
      return { user: null };
    }
  }
});
```

---

## 6. CVEs & Real-World Examples

### CVE-2024-50312 — GraphQL Introspection Improper Access Control
- **Description**: Vulnerability in GraphQL due to improper access controls on the introspection query, allowing unauthorized users to enumerate the entire schema, discover hidden fields, and plan targeted attacks
- **Affected**: Multiple GraphQL implementations
- **CVSS**: 5.3 (Medium)
- **Fix**: Disable introspection in production; implement schema-allow-list for internal tools
- **Source**: https://nvd.nist.gov/vuln/detail/CVE-2024-50312

### CVE-2024-40094 — graphql-java Introspection Denial of Service
- **Description**: GraphQL Java fails to account for ExecutableNormalizedFields (ENFs) when preventing DoS; a crafted introspection query with deeply nested aliases forces excessive CPU/memory work and can exhaust the server
- **Affected**: graphql-java before 21.5 (also fixed in 20.9 and 19.11)
- **CVSS**: 5.3 (Medium, CVSS 3.1) / 8.7 (CVSS 4.0)
- **Fix**: Upgrade graphql-java to 21.5+ (or 20.9 / 19.11); enforce query depth/complexity limits and restrict introspection
- **Source**: https://nvd.nist.gov/vuln/detail/CVE-2024-40094

### GraphQL Batching Attack — Facebook/Rewards Bypass (HackerOne)
- **Description**: Researcher discovered that a GraphQL endpoint allowed batch queries to perform credential stuffing attacks with 50+ login attempts in a single HTTP request, bypassing per-request rate limits
- **Bounty**: $3,000
- **Fix**: Implement per-operation rate limiting; limit batch size; disallow batched mutations
- **Source**: https://medium.com/@amindaimond1/graphql-batching-attacks-my-wild-ride-into-modern-api-vulnerabilities-4161b888dead

### Shopify GraphQL Information Disclosure (Assetnote research — no CVE)
- **Description**: Improper field-level authorization in GraphQL resolvers allowed authenticated users to query metadata about resources they should not have access to, via indirect relationship traversal
- **Affected**: Shopify GraphQL API (bug-bounty / research finding, no assigned CVE)
- **Fix**: Implement field-level authorization in all resolvers, not just top-level queries
- **Source**: https://www.assetnote.io/resources/research/exploiting-graphql

---

## References

- [PortSwigger Web Security Academy — GraphQL API Vulnerabilities](https://portswigger.net/web-security/graphql)
- [Imperva — GraphQL Vulnerabilities and Common Attacks](https://www.imperva.com/blog/graphql-vulnerabilities-and-common-attacks-seen-in-the-wild/)
- [Apollo — Securing Your GraphQL API from Malicious Queries](https://www.apollographql.com/blog/graphql/security/securing-your-graphql-api-from-malicious-queries/)
- [OWASP — GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [Escape — How to Secure GraphQL APIs](https://escape.tech/blog/how-to-secure-grpc-apis/)
