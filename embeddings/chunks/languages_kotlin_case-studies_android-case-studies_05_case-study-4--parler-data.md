---
source: "languages/kotlin/case-studies/android-case-studies.md"
title: "Android / Kotlin Case Studies"
heading: "Case Study 4: Parler Data Breach — Android Content Provider Metadata Leak"
category: "case-study"
language: "kotlin"
severity: "high"
tags: [case, case-study, kotlin, references, study]
chunk: 5/6
---

## Case Study 4: Parler Data Breach — Android Content Provider Metadata Leak

### Incident Overview
- **Date**: January 2024 (re-audit of 2021 breach)
- **Platform**: Android
- **Severity**: High (location data, private posts, user metadata)

### Description
The Parler social media app suffered a massive data breach in 2021, but a 2024 re-audit revealed that the Android app's exported **Content Provider** leaked geolocation metadata from every user post, even when location sharing was "disabled" in the UI. The provider exposed EXIF-like data embedded in media uploads, including GPS coordinates, device model, and timestamps.

### Technical Analysis
The Android Parler app had an exported content provider (`android:exported="true"`) that exposed internal media metadata, including GPS coordinates from EXIF data, device identifiers, and server-side timestamps. The provider had no permission check.

### Impact
- Public exposure of user GPS locations (home addresses, workplaces)
- Private posts' metadata leaked even for locked/private accounts
- Timelines of user activity reconstructable from timestamps

### Lessons for Android Developers
1. **Check ALL exported components** for unnecessary data exposure
2. Content Providers should **never** be exported without strict permission requirements
3. Strip EXIF/location metadata from media before storing or exposing via providers
4. Use "signature" protection level for custom permissions to limit access to your app only

### Sources
- https://salt.security/blog/unpacking-the-parler-data-breach
- https://cyberweapons.medium.com/critical-android-bug-insecure-exported-components-content-leak-a-real-world-writeup-dada800f7ee6

---