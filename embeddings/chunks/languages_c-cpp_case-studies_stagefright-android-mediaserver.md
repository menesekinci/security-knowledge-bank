---
source: "languages/c-cpp/case-studies/stagefright-android-mediaserver-rce-2015.md"
title: "Stagefright (2015): Android's C++ Media Library Remote Code Execution"
category: "case-study"
language: "c-cpp"
severity: "high"
tags: [c-cpp, case-study, cause, exploitation, impact, overview, root]
---

# Stagefright (2015): Android's C++ Media Library Remote Code Execution

**Language:** C++ (Android's libstagefright)
**Vulnerability Type:** Multiple Memory Corruption (Heap Overflow, Integer Overflow)
**CVE:** Multiple (CVE-2015-1538, CVE-2015-1539, CVE-2015-3824, etc.)
**Date:** Publicly disclosed at BlackHat 2015
**Impact:** Up to 950 million Android devices vulnerable remotely

## Overview

**Stagefright** was a landmark security vulnerability that shook the mobile world. Discovered by **Joshua "jduck" Drake** of Zimperium, it consisted of multiple memory corruption bugs in Android's **libstagefright** media processing library. The critical insight: these bugs could be exploited **remotely via MMS (text message)** — an attacker who knew only your phone number could compromise your device without any user interaction.

The vulnerabilities affected **approximately 950 million Android devices** — virtually every Android device at the time (Android 2.2 through 4.0, and 5.0+).

## Root Cause

Android's media processing was handled by a library called **libstagefright**, which ran inside the **mediaserver** process. When an app (messenger, browser, etc.) received a video file — for example, an MPEG-4 (.mp4) file sent via MMS — the file was parsed by libstagefright.

The MPEG-4 parsing code was **sketchy and undertested** (in jduck's words). By writing a simple fuzzer for MPEG-4 files, he found multiple crashes pointing to memory corruption issues. Manual auditing revealed several classes of bugs:

1. **Integer overflows** in size calculations for sample tables
2. **Heap buffer overflows** when copying data into fixed-size buffers
3. **Stack buffer overflows** in metadata handling
4. **Use-after-free** conditions in processing error paths

The most famous exploit (CVE-2015-1538) leveraged a heap overflow in the `tx3g` (text track) parsing — a feature that handles 3GPP timed text subtitles in video files.

## Why It Was Uniquely Dangerous

Stagefright was terrifying because of the **attack vector**: **MMS (text messaging)**. When an MMS arrived on an Android device, the messaging app would automatically download and process the message (including any attached media) to show a preview notification. No user interaction required.

This meant:
1. Attacker sends a crafted MMS to the victim's phone number
2. The victim's phone automatically processes the malicious video file
3. The mediaserver process is compromised
4. The attacker gains a foothold on the device

## Exploitation

The exploit was not trivial but was feasible:

- **ASLR bypass** was achieved via heap spray (32-bit address space made this practical)
- **Brute-force** of libc base address was possible because mediaserver restarted after crashes (~5 second delay)
- Successful exploitation took **30 seconds to 1 hour**
- **Pivoting** to full device compromise (kernel exploit) was required since mediaserver is sandboxed
- Later improvements (by Hanan Be'er, "Metaphor" exploit) added info leak techniques for more reliable exploits

## Impact on Android Security

Stagefright was a **watershed moment** for Android security. It forced Google to fundamentally rethink mobile platform security:

1. **Monthly security patches** — Android introduced the monthly security bulletin program, now standard across the industry
2. **Media server hardening** — libstagefright was decomposed into smaller, sandboxed components
3. **SELinux policies** — tightened to restrict the mediaserver process
4. **ASLR improvements** — better address space randomization
5. **Compiler hardening** — CFI (Control Flow Integrity) and other mitigations became standard
6. **Fuzzing investment** — Google began heavily investing in fuzzing media libraries (OSS-Fuzz was later created)
7. **Android permission model** — apps no longer automatically trust MMS content

## Key Takeaways for Developers

1. **C++ memory safety is hard, especially in complex parsers.** Media formats (MP4, AVI, etc.) are notoriously complex and full of edge cases.
2. **Attack surface matters.** If a library processes untrusted data automatically (no user interaction required), it's a critical attack surface.
3. **Fuzzing catches what code review misses.** The bugs were found by writing a simple fuzzer. Even basic fuzzing finds real vulnerabilities.
4. **Compartmentalization is key.** Modern Android sandboxes each media codec separately — compromise of one doesn't mean compromise of the whole device.
5. **Monthly updates save lives (digitally).** Before Stagefright, Android updates were sporadic. The monthly cadence dramatically reduced the window of vulnerability.

## References

- [Isosceles - The Legacy of Stagefright](https://blog.isosceles.com/the-legacy-of-stagefright/)
- [Zimperium - Stagefright CVE-2015-1538](https://zimperium.com/blog/the-latest-on-stagefright-cve-2015-1538-exploit-is-now-available-for-testing-purposes/)
- [Google Project Zero - Stagefrightened](https://googleprojectzero.blogspot.com/2015/09/stagefrightened.html)
- [USENIX - Stagefright Slides](https://www.usenix.org/sites/default/files/conference/protected-files/woot16_slides_drake.pdf)
- [Exploit-DB - Metaphor Stagefright Exploit](https://www.exploit-db.com/docs/english/39527-metaphor---a-(real)-real-%C2%ADlife-stagefright-exploit.pdf)
