---
source: "languages/swift/swiftui-security.md"
title: "🍎 SwiftUI Security Guide"
heading: "6. Background Task Security"
category: "language-vuln"
language: "swift"
severity: "medium"
tags: [data, deep, injection, language-vuln, navigationlink, preview, swift, swiftui]
chunk: 7/9
---

## 6. Background Task Security

```swift
// VULNERABLE: BGTaskScheduler without authentication check
func registerBackgroundTask() {
    BGTaskScheduler.shared.register(forTaskWithIdentifier: "com.app.refresh", using: nil) { task in
        handleBackgroundRefresh(task: task as! BGAppRefreshTask)
    }
}

func handleBackgroundRefresh(task: BGAppRefreshTask) {
    // ⚠️ No auth check — runs with whatever credentials were last stored
    fetchSensitiveUserData()
}

// SECURE: Verify session validity before background work
func handleBackgroundRefresh(task: BGAppRefreshTask) {
    task.expirationHandler = { task.setTaskCompleted(success: false) }
    
    Task {
        guard await authService.hasValidSession() else {
            task.setTaskCompleted(success: false)
            return
        }
        await fetchSensitiveUserData()
        task.setTaskCompleted(success: true)
    }
}
```

---