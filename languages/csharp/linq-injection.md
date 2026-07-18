# 🔴 LINQ Injection & Expression Tree Manipulation

## What Is It?

LINQ Injection occurs when user input is unsafely incorporated into dynamic LINQ queries. The **Dynamic LINQ** (`System.Linq.Dynamic`) library allows building and executing queries as strings — opening an attack vector similar to SQL Injection.

Expression Trees are LINQ's fundamental building block. They transform queries written like code at compile-time into data structures that can be inspected at runtime. Attackers can manipulate this tree to alter the original query's logic.

## How Does It Appear in Vibe Coding?

```
Prompt: "User search page — sort by name, age, city"
AI: "Let me directly add the sort parameter using Dynamic LINQ"
— This invites LINQ Injection!
```

## CVE-2023-32571: Dynamic LINQ RCE

**CVE:** CVE-2023-32571
**CVSS:** 9.8 (Critical)
**Affected:** Dynamic Linq 1.0.7.10 - 1.2.25
**Source:** https://nvd.nist.gov/vuln/detail/CVE-2023-32571

Discovered by NCC Group, this critical security vulnerability allows **RCE** when unsafe input is passed to Dynamic LINQ methods like `Where()`, `Select()`, `OrderBy()`.

### Vulnerable Code Example

```csharp
// 💀 DANGEROUS — Dynamic LINQ Injection
public IQueryable<User> SearchUsers(string filter)
{
    // User input is directly added to the LINQ query
    return context.Users.Where(filter);
    // Input: "1=1)" — returns all users
    // Input: "Users.Any() ? 1 : 1" — DoS
    // Input: more complex expressions can lead to RCE
}
```

### PoC

```csharp
// CVE-2023-32571 PoC (simplified)
// Vulnerable Dynamic LINQ query:
var query = db.Products.Where("CategoryId = " + userInput);

// Attacker input:
userInput = "1) ? 1 : 1";  // Boolean exploitation
// or:
userInput = "1 && Users.Any() && 1";  // Cross-table access
```

**PoC Source:** https://github.com/Tris0n/CVE-2023-32571-POC
**Fox-IT Analysis:** https://www.fox-it.com/nl/dynamic-linq-injection-remote-code-execution-vulnerability-cve-2023-32571/

## Expression Tree Manipulation

Expression trees can be created and modified at runtime. An attacker can:

1. **Change method calls** — Turn a comparison in `Where()` into `||` (OR)
2. **Redirect property access** — Access sensitive fields
3. **Add new nodes** — Completely change query logic

### Vulnerable Expression Tree Usage

```csharp
// 💀 DANGEROUS — manual expression tree creation
public static Expression<Func<T, bool>> BuildPredicate<T>(
    string propertyName, string op, object value)
{
    var param = Expression.Parameter(typeof(T), "x");
    var member = Expression.Property(param, propertyName);
    var constant = Expression.Constant(value);
    
    // Operator comes from the user — can be manipulated!
    Expression body;
    switch (op)
    {
        case "==": body = Expression.Equal(member, constant); break;
        case ">": body = Expression.GreaterThan(member, constant); break;
        // ... 
    }
    
    return Expression.Lambda<Func<T, bool>>(body, param);
}

// Input: propertyName = "PasswordHash"
// Query could filter password hashes!
```

## SQL Injection via LINQ to Entities

While LINQ to Entities is generally safe, developers open the door to SQL Injection when using `FromSqlRaw()` or `ExecuteSqlRaw()`.

```csharp
// 💀 DANGEROUS — Raw SQL + LINQ mixture
var query = context.Users
    .Where(u => u.IsActive)
    .FromSqlRaw($"SELECT * FROM Users WHERE Name LIKE '%{search}%'");
    // SQL Injection!
```

## Detection & Prevention

### Detection

- Usage of Dynamic LINQ (`System.Linq.Dynamic`)
- Calls to `FromSqlRaw()` / `ExecuteSqlRaw()`
- User input in expression trees
- Building LINQ queries via string concatenation

### Prevention

```csharp
// ✅ SAFE — LINQ query directly instead of Expression
var users = context.Users
    .Where(u => u.Name.Contains(search) && u.Age > minAge);

// ✅ SAFE — Parameterized SQL
var users = context.Users
    .FromSqlInterpolated($"SELECT * FROM Users WHERE Name LIKE '%{search}%'");

// ✅ SAFE — Dynamic LINQ alternative: predicate builder
var predicate = PredicateBuilder.New<User>();
predicate = predicate.And(u => u.IsActive);
if (!string.IsNullOrEmpty(search))
    predicate = predicate.And(u => u.Name.Contains(search));
```

## References

- https://nvd.nist.gov/vuln/detail/CVE-2023-32571
- https://www.fox-it.com/nl/dynamic-linq-injection-remote-code-execution-vulnerability-cve-2023-32571/
- https://github.com/Tris0n/CVE-2023-32571-POC
- https://insinuator.net/2016/10/linq-injection-from-attacking-filters-to-code-execution/
- https://learn.microsoft.com/en-us/dotnet/csharp/advanced-topics/expression-trees/
- https://stackoverflow.com/questions/79463021/entity-framework-core-how-safe-are-expressions-from-sql-injection
