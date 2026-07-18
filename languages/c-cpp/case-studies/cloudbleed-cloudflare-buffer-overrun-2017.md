# Cloudbleed (2017): Cloudflare's Buffer Overrun That Leaked Private Data

**Language:** C (Ragel-generated HTML Parser)
**Vulnerability Type:** Buffer Overrun (Missing `fhold` in Ragel State Machine)
**Date:** February 2017 (bug existed for years, actively leaking for ~6 days)
**Impact:** Sensitive data from ~2 million Cloudflare customer websites leaked

## Overview

**Cloudbleed** was a devastating buffer overrun bug in **Cloudflare's edge server infrastructure**, discovered by **Tavis Ormandy** of Google's **Project Zero** in February 2017. The bug caused Cloudflare's servers to return **chunks of uninitialized memory** containing sensitive data from other customers — including HTTP cookies, authentication tokens, POST body data, and private messages.

The data was leaked into HTTP responses served to regular visitors, and worst of all, **some of this data was cached by search engines** like Google, making it publicly searchable.

Cloudflare served approximately **2 million websites** at the time, making the potential impact massive.

## Root Cause

The bug was a classic C pointer arithmetic error in an HTML parser that Cloudflare used for on-the-fly page modifications (email obfuscation, HTTPS rewrites, server-side excludes).

The parser was built using **Ragel**, a state machine compiler that generates C code. The generated code included this pattern:

```c
/* generated code */
if ( ++p == pe )
    goto _test_eof;
```

The root cause: **reaching the end of a buffer was checked using `==` (equality) instead of `>=` (greater-than-or-equal)**. A pointer could step **past** the end of the buffer (e.g., `p = pe + 1`), and the equality check would never trigger.

This happened because the Ragel state machine code for the `$lerr` (error handler) was missing an `fhold` statement:

```
$lerr{ dd("script consume_attr failed");
       fgoto script_consume_attr; };
```

The `$lerr` error handler did `fgoto` (jump to another state) but **did not do `fhold` (decrement the pointer back by one)**. The `fhold` is equivalent to `p--` and is essential because when the error condition occurs, `p` is pointing past the valid data. Without `fhold`, the pointer could jump over the end of the buffer.

This would happen when a web page ended with a **broken HTML tag** like `<script type=`. While rare (~0.06% of websites), Cloudflare processes billions of requests, so this edge case was hit frequently.

## Why Now? The Timing

The underlying bug had existed in Cloudflare's Ragel-based parser **for years** without causing issues. It was triggered when Cloudflare introduced a **new parser (cf-html)** alongside the old one. The new parser subtly changed how NGINX buffers were handled, which exposed the latent buffer overrun in the old parser.

The three features that triggered the vulnerable code path:
1. **Email Obfuscation** (changed on Feb 13 — primary cause of leaks)
2. **Automatic HTTPS Rewrites**
3. **Server-Side Excludes**

## The Discovery

Tavis Ormandy's proof of concept returned:
> "private messages from major dating sites, full messages from a well-known chat service, online password manager data, frames from adult video sites, hotel bookings. We're talking full HTTPS requests, client IP addresses, full responses, cookies, passwords, keys, data, everything."

## Response Timeline

- **Feb 17 (late):** Ormandy reports to Cloudflare
- **47 minutes later:** Email Obfuscation disabled globally (primary leak stopped)
- **3 hours later:** HTTPS Rewrites disabled
- **~6 hours later:** Server-Side Excludes patched and disabled
- **7 hours:** Complete global fix deployed (industry standard for this type of bug: 3 months)

## Impact Scale

- **1 in every 3,300,000 HTTP requests** leaked memory (0.00003%)
- **18 million+ HTTP responses** potentially contained leaked memory
- Greatest impact window: **Feb 13–18, 2017**
- Search engine caches stored leaked data
- Customers affected: Uber, OkCupid, Fitbit, 1Password (minimal exposure), and millions of others

## Aftermath

- Cloudflare's own private key (for machine-to-machine encryption) was among the leaked data
- No evidence of malicious exploitation was found
- The bug name "Cloudbleed" was coined by Tavis Ormandy as a deliberate comparison to Heartbleed

## Key Takeaways for Developers

1. **Use `>=` not `==` for bounds checks.** Buffer bounds checks must catch the case where the pointer has *crossed* the boundary, not just landed exactly on it.
2. **Edge cases are where security bugs hide.** The bug only triggered on broken HTML at the end of a buffer (~0.06% of pages) — but that was enough to compromise millions of sites.
3. **Legacy code + new code = unexpected interactions.** The old parser was fine alone. The new parser changed buffer handling and exposed the latent bug.
4. **Feature flags (global kills) save time.** Cloudflare could disable the affected features globally in minutes, not hours or days.

## References

- [Cloudflare - Incident Report](https://blog.cloudflare.com/incident-report-on-memory-leak-caused-by-cloudflare-parser-bug/)
- [Wikipedia - Cloudbleed](https://en.wikipedia.org/wiki/Cloudbleed)
- [Google Project Zero Issue Tracker](https://bugs.chromium.org/p/project-zero/issues/detail?id=1139)
- [The Hacker News - Cloudbleed Coverage](https://thehackernews.com/2017/02/cloudflare-vulnerability.html)
