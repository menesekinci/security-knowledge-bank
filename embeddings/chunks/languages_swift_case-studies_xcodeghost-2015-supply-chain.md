---
source: "languages/swift/case-studies/xcodeghost-2015-supply-chain.md"
title: "iOS XcodeGhost (2015) — Swift Supply Chain"
category: "case-study"
language: "swift"
severity: "critical"
tags: [case-study, cause, happened, impact, root, swift, system, target, what, when]
---

# iOS XcodeGhost (2015) — Swift Supply Chain

## 📅 When Did It Happen?
September 2015

## 🎯 Target System
Apple iOS — Chinese iOS developers via Xcode (development environment)

## 🔴 What Happened?
Chinese developers downloaded Xcode from **other sources** instead of Apple's slow Chinese download.
- The attacker added malware to Xcode (XcodeGhost) and distributed it on popular Chinese file-sharing sites
- When developers compiled apps using this Xcode, the malware infected the apps
- **4,000+ apps** affected (WeChat, Didi Chuxing, Railway 12306 — some of China's most popular apps)
- Stolen data: device info, app info, keywords

## 🧠 Root Cause
1. **Compilation tool from untrusted source**: Developers used fast download sites instead of the official App Store
2. **Missing code signing**: Xcode's integrity was not verified
3. **No Xcode certificate verification**: Apple's signature was not checked

## 💥 Impact
- 4,000+ iOS apps infected with malware
- ~128 million iOS users affected (per figures disclosed in Apple internal emails during the 2021 Epic v. Apple trial)
- Apple had to increase Xcode download speed in China
- Trust in iOS security was shaken

## 🎓 Lessons Learned
- **Download build tools from official sources** (App Store, brew, chocolatey)
- **Verify code signature**: macOS: `codesign -dv /Applications/Xcode.app`
- **Check Xcode's hash**: Compare with Apple's published SHA
- **Verify images used in your CI/CD pipeline**

## Vibe Coding Connection
When AI generates Swift/iOS code:
- Verify libraries from Swift package manager
- Add "only add packages from official sources" to the prompt
- Check Xcode version

## 🔗 Source
- https://researchcenter.paloaltonetworks.com/2015/09/xcodeghost/
- https://en.wikipedia.org/wiki/XcodeGhost
