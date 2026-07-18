---
source: "languages/swift/case-studies/ios-case-studies.md"
title: "iOS / Swift Case Studies"
heading: "Case Study 3: Apple 'Sign in with Apple' Authentication Bypass ($100,000 Bounty)"
category: "case-study"
language: "swift"
severity: "critical"
tags: [case, case-study, references, study, swift]
chunk: 4/6
---

## Case Study 3: Apple "Sign in with Apple" Authentication Bypass ($100,000 Bounty)

### Incident Overview
- **Date**: May 2020 (disclosed June 2020)
- **Bounty**: $100,000
- **Researcher**: Bhavuk Jain
- **Severity**: Critical (complete account takeover)

### Description
Bhavuk Jain discovered a critical authentication bypass in Apple's **server-side** "Sign in with Apple" (SIWA) implementation. The flaw let an attacker **take over any user's account** on any third-party service that used SIWA. The bug was **not** a client-side `aud`-claim mistake or a forged/self-signed token — it was that **Apple's own authorization server would issue a validly-signed JWT for *any* email the requester asked for**, without verifying that the requester was actually authorized for that email.

### Root Cause
After a user authenticates to Apple, SIWA hands the app a JWT (signed by Apple, verified against Apple's public keys) whose `email`/`sub` claims identify the user. Bhavuk found that, once authenticated to Apple with **his own** Apple ID, he could ask Apple's server to generate a JWT for an **arbitrary email address** — and Apple would return a **genuinely, correctly signed** token bound to that victim's email. Because the token's signature was legitimately Apple's, every third-party service that (correctly) verified the signature against Apple's public key accepted it as proof of the victim's identity. The failure was Apple **not validating the token requester** against the requested email, not any signature or `aud` weakness on the relying party.

### Technical Detail
```text
# Attack flow (the real one):
# 1. Attacker authenticates to Apple normally, with the ATTACKER's own Apple ID.
# 2. Attacker requests a SIWA JWT from Apple's server but supplies the VICTIM's email.
# 3. Apple's server generates and *validly signs* a JWT whose email/sub = the victim.
#    (No check that the attacker owns or is authorized for that email — the core bug.)
# 4. Attacker presents this Apple-signed JWT to any third-party app using SIWA.
# 5. The app verifies the signature against Apple's public key -> it is genuinely valid.
# 6. The app logs the attacker in as the VICTIM -> full account takeover.
```

### Impact
- Any third-party app using "Sign in with Apple" for login could be compromised
- Complete account takeover of any user, even those who never linked SIWA to that app
- Affected relying parties on all platforms (iOS, web, Android) that trusted Apple's tokens

### Fix
The fix was on **Apple's side**: Apple corrected its server so it **validates that the token requester is authorized for the requested email** before issuing/signing a JWT. Apple also investigated its logs and reported no evidence of prior abuse. Because the vulnerable tokens were genuinely Apple-signed, relying-party `aud`/signature checks could **not** have stopped this attack — only Apple could.

### Lessons for iOS Developers
1. This class of bug lives in the **identity provider**, not the relying party — a validly signed token can still assert an identity the requester was never authorized to claim
2. Where possible, complete SIWA on your **backend** via Apple's `authorizationCode` → `/auth/token` exchange rather than trusting an `id_token` handed over by the client
3. Still validate `iss`, `aud`, `exp`, and the signature on your backend — necessary hygiene, though it would not have blocked this particular Apple-side flaw
4. Prefer the `sub` (stable user identifier) over `email` for account linking, since email can be a relay/private address

### Sources
- https://bhavukjain.com/blog/2020/05/30/zeroday-signin-with-apple
- https://samcurry.net/hacking-apple

---