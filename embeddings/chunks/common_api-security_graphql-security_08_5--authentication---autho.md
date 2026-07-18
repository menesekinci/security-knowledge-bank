---
source: "common/api-security/graphql-security.md"
title: "GraphQL Security"
heading: "5. Authentication & Authorization in Resolvers"
category: "api-security"
language: "common"
severity: "medium"
tags: [api-security, attacks, batching, depth, introspection, leaks, overview, query, table]
chunk: 8/10
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