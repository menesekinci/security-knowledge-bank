---
source: "languages/java/sql-injection.md"
title: "SQL Injection in Java — JDBC, JPA/Hibernate Misuse"
category: "language-vuln"
language: "java"
severity: "medium"
tags: [ai-generated, hibernate, java, jdbc, language-vuln, overview, vulnerability]
---

# SQL Injection in Java — JDBC, JPA/Hibernate Misuse

## Overview

SQL injection remains one of the most common and dangerous web vulnerabilities, and Java is no exception. Despite JDBC's `PreparedStatement` API (used safely since 1997) and ORMs like Hibernate with built-in parameterization, AI-generated Java code consistently introduces SQL injection vulnerabilities.

## Why AI Generates SQL Injection in Java

LLMs generate vulnerable SQL patterns because:
1. They mix string concatenation with SQL (old tutorials, forum posts)
2. They use JPA's `@Query` with string concatenation
3. They use Hibernate's `createQuery` with string building
4. They generate `Statement` objects instead of `PreparedStatement`
5. They use JPA "LIKE" queries with injected wildcards

## JDBC: The Classic Pattern

### AI-Generated Vulnerability: Statement + Concatenation

```java
// AI-GENERATED — uses Statement with string concatenation
public User getUserById(String userId) throws SQLException {
    String sql = "SELECT * FROM users WHERE id = '" + userId + "'";
    // BUG: userId = "1' OR '1'='1"
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery(sql);
    // ...
}
```

**Exploit**: `userId = 1' UNION SELECT username, password FROM admins --`

**Secure Fix**:
```java
public User getUserById(String userId) throws SQLException {
    String sql = "SELECT * FROM users WHERE id = ?";
    PreparedStatement pstmt = connection.prepareStatement(sql);
    pstmt.setString(1, userId);  // Safe: JDBC escapes/parameterizes this
    ResultSet rs = pstmt.executeQuery();
    // ...
}
```

### AI-Generated Vulnerability: Order By Injection

```java
// AI-GENERATED — tries to parameterize ORDER BY (doesn't work)
@GetMapping("/users")
public List<User> getUsers(@RequestParam String sortBy) {
    String sql = "SELECT * FROM users ORDER BY ?";
    PreparedStatement pstmt = connection.prepareStatement(sql);
    pstmt.setString(1, sortBy);  // BUG: ORDER BY doesn't support ? placeholders!
    // The ? gets treated as a literal string, not a column reference
}
```

**Secure Fix**: Whitelist allowed column names.
```java
private static final Set<String> ALLOWED_SORT_COLUMNS = Set.of(
    "name", "email", "id", "created_at"
);

public List<User> getUsers(String sortBy) {
    if (!ALLOWED_SORT_COLUMNS.contains(sortBy)) {
        sortBy = "id"; // Default
    }
    // SORT BY is safe here because sortBy was validated against a whitelist
    String sql = "SELECT * FROM users ORDER BY " + sortBy;
    // Note: column names CANNOT be parameterized in JDBC
    // The security is in the whitelist, not the escaping
    Statement stmt = connection.createStatement();
    // ...
}
```

## JPA/Hibernate: Common Pitfalls

### AI-Generated Vulnerability: @Query with Concatenation

```java
// AI-GENERATED — string concatenation in @Query
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    @Query("SELECT u FROM User u WHERE u.name = '" + "#{#name}" + "'")
    // BUG: The concatenated string is vulnerable to injection!
    // The #{} syntax is SpEL, not parameterized binding
    List<User> findByName(String name);
}
```

**Secure Fix**: Use named parameters.
```java
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    @Query("SELECT u FROM User u WHERE u.name = :name")
    List<User> findByName(@Param("name") String name);
}
```

### AI-Generated Vulnerability: Native Queries

```java
// AI-GENERATED — native SQL with concatenation
@Query(value = "SELECT * FROM users WHERE name = '" + "#{#name}" + "'", 
       nativeQuery = true)
List<User> findByNameNative(String name);
```

**Secure Fix**: Native queries still support parameterization.
```java
@Query(value = "SELECT * FROM users WHERE name = :name", nativeQuery = true)
List<User> findByNameNative(@Param("name") String name);
```

### AI-Generated Vulnerability: Hibernate Criteria Injection

```java
// AI-GENERATED — uses string concatenation with Hibernate
public List<User> searchUsers(String searchTerm) {
    String jpql = "FROM User WHERE name LIKE '%" + searchTerm + "%'";
    // BUG: searchTerm = "%' OR 1=1 OR name LIKE '%
    return entityManager.createQuery(jpql, User.class).getResultList();
}
```

**Secure Fix**: Use parameterized JPQL.
```java
public List<User> searchUsers(String searchTerm) {
    return entityManager
        .createQuery("FROM User WHERE name LIKE :searchTerm", User.class)
        .setParameter("searchTerm", "%" + searchTerm + "%")
        .getResultList();
}
```

### AI-Generated Vulnerability: Spring Data JPA Specification Injection

```java
// AI-GENERATED — specification with unsafe concatenation
public Specification<User> nameLike(String name) {
    return (root, query, builder) -> 
        builder.like(root.get("name"), "%" + name + "%");
    // This is actually safe if using CriteriaBuilder.like()
    // But AI often writes:
    // builder.like(root.get("name"), "%" + name + "%");
    // The % wildcard itself is safe; the binding is parameterized
}
```

## AI-Generated Vulnerability: MyBatis Mapper Injection

```java
// AI-GENERATED MyBatis mapper — uses ${} instead of #{}
@Select("SELECT * FROM users WHERE name = '${name}'")
// BUG: ${} is direct string substitution — injection!
List<User> findByName(@Param("name") String name);
```

**Secure Fix**: Use `#{}` for parameterized binding.
```java
@Select("SELECT * FROM users WHERE name = #{name}")
List<User> findByName(@Param("name") String name);
```

## Real CVEs

- **CVE-2024-1597 (PostgreSQL JDBC / pgjdbc)**: CVSS 9.8 — SQL injection in the PostgreSQL JDBC driver when `PreferQueryMode=SIMPLE` is set (not the default). With a numeric placeholder immediately preceded by a minus and a following string placeholder on the same line, a crafted string value can break out and inject SQL, defeating the protection that parameterized queries normally provide. Fixed in pgjdbc 42.7.2 (and 42.2.28/42.3.9/42.4.4/42.5.5/42.6.1 back-ports).
- **CVE-2022-31197 (PostgreSQL JDBC / pgjdbc)**: CVSS 8.0 — The pgjdbc implementation of `ResultSet.refreshRow()` did not properly escape column names, so a column name containing a statement terminator (e.g. a semicolon) could inject SQL. Exploitable when application code passes attacker-influenced column names to `refreshRow()`. Fixed in pgjdbc 42.2.26 and 42.4.1.

## Detection

```bash
# Find SQL injection patterns in Java
grep -rn "executeQuery\|executeUpdate\|execute(" src/ | grep -v "PreparedStatement"
grep -rn "createQuery\|createNativeQuery" src/ | grep -v "setParameter"
grep -rn '@Query.*+' src/  # Concatenation in JPQL

# Find MyBatis ${} injection
grep -rn '\$\{' src/main/resources/

# Static analysis with FindSecBugs
mvn com.h3xstream.findsecbugs:findsecbugs-plugin:findsecbugs
```

## Prevention Checklist

1. **Always use `PreparedStatement`** — Never `Statement` for queries with user input.
2. **Always use named/bind parameters** — `:param` in JPQL, `?` in JDBC, `#{}` in MyBatis.
3. **Never concatenate SQL strings** — Not even for "simple" queries.
4. **Use JPA Criteria API** — Type-safe query building avoids string concatenation entirely.
5. **Whitelist ORDER BY and column names** — These cannot be parameterized.
6. **Use parameter binding for LIKE** — `setParameter("name", "%" + input + "%")` — the `%` is data, not SQL syntax.
7. **Run FindSecBugs / SpotBugs with security plugin** — Automated detection.
8. **Review all `@Query` annotations** — Especially ones with `nativeQuery=true`.
9. **Use Hibernate's `setParameter`** — Never `String.format` for query strings.
10. **Apply least privilege** — Database user should only have necessary permissions (e.g., read-only for SELECT queries).
