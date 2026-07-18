---
source: "languages/go/cgo-security.md"
title: "🐹 Go CGo Security"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [callback, common, go, handling, language-vuln, protection, safety, string]
---

# 🐹 Go CGo Security

## C String Handling
When passing a string to C, the **null-terminated** conversion is critical.

```go
// VULNERABLE:
package main

/*
#include <stdio.h>
void print_msg(char* s) { printf("%s", s); }
*/
import "C"
import "unsafe"

func Print(msg string) {
    cs := C.CString(msg)  // Go string → C string
    C.print_msg(cs)
    C.free(unsafe.Pointer(cs)) // IF FREE IS FORGOTTEN → memory leak!
}
```

## C callback safety
```go
// VULNERABLE callback:
/*
typedef void (*callback_t)(int);
void register_cb(callback_t cb) { cb(42); }
*/
import "C"

//export goCallback
func goCallback(val C.int) {
    // Go panic → on the C stack → UB!
}
```

## Common CGo memory bug: unterminated / overflowing string conversion
`C.CString` allocates a NUL-terminated copy; forgetting to `C.free` it leaks
memory, and passing raw Go `[]byte`/pointers into C without accounting for the
terminator can overflow. Check advisories in the official Go vulnerability
database (format `GO-YYYY-NNNN`) at https://pkg.go.dev/vuln.

## Protection
- Pair every `C.CString` call with a `defer C.free`
- Don't use `recover()` in C callbacks (it doesn't propagate to C)
- Use pure Go instead of cgo when possible
- Test cgo code with `-fsanitize=memory`

**Source:** Go vulnerability database — https://pkg.go.dev/vuln (IDs use the `GO-YYYY-NNNN` format)
