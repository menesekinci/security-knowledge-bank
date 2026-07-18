# 🐘 PHP SQL Injection

## Example (Dangerous)
```php
// 💀 VULNERABLE:
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = $id";  // Direct concatenation!
$result = mysqli_query($conn, $query);

// ✅ SECURE (MySQLi prepared statement):
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();
$result = $stmt->get_result();

// ✅ Or PDO:
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
```

## The Most Common Mistakes the AI Makes
- Uses `mysqli_real_escape_string()` but it is **NOT enough** (encoding bypass)
- Uses `addslashes()` — does not protect against injection
- Uses the old mysql_* functions (removed in PHP 7!)

## Rule
- Use **PDO prepared statements** (the safest)
- `mysqli_real_escape_string()` is **not safe on its own**
- Never build SQL with string concatenation

---

**Severity: 🔴 Critical**
