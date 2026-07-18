# 🌊 Kotlin Null Safety Bypass

### What Is It?
Kotlin's null safety system (`?` and `!!`) is powerful, but AI creates a
**NullPointerException** risk by using the `!!` operator unnecessarily.

## Example
```kotlin
// 💀 What the AI wrote:
val user = getUser()  // User?
val name = user!!.name  // !! → NPE if user is null!

// ✅ Safe:
val name = user?.name ?: "default"
// Or:
val name = user?.name ?: return ResponseEntity.badRequest().build()
```

## The Mistakes AI Makes Most Often
- "Guaranteeing" non-null with `!!` — blows up at runtime
- Using `lateinit var` before initializing it
- Skipping null checks on delegated properties
- Not reading nullability annotations in Java interop

## Prevention
- Don't use `!!` — use `?.` (safe call) or `?:` (elvis)
- Use `lateinit` only for values injected via DI
- Use `requireNotNull()`, `checkNotNull()`
- Watch for `@Nullable`/`@NonNull` annotations in Java interop

---

**Severity: 🟡 Medium** — NullPointerException, crash.
