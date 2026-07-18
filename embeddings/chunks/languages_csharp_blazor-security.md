---
source: "languages/csharp/blazor-security.md"
title: "🔴 Blazor WASM/Server Security"
category: "language-vuln"
language: "csharp"
severity: "critical"
tags: [blazor, csharp, does, framework-specific, language-vuln, server, wasm, what]
---

# 🔴 Blazor WASM/Server Security

## What Is It?

Blazor runs on two hosting models:
- **Blazor Server**: UI components run on the server, DOM updates are sent to the browser via **SignalR**
- **Blazor WASM**: UI runs in the browser with WebAssembly, API communication is over standard HTTP

Each model has its own specific security risks.

## How Does It Appear in Vibe Coding?

```
Prompt: "Build an admin panel with Blazor Server — delete user on button click"
AI: "Writes a direct method. But skips authorization checks!"
```

## Blazor Server — SignalR & Circuit Security

In Blazor Server, a **SignalR circuit** is created for each user. This circuit maintains server-side state. Security vulnerabilities:

### 1. Circuit Hijacking

A Blazor Server circuit is tied to a SignalR connection ID. If an attacker steals this ID, they can hijack the user's session.

```csharp
// 💀 Blazor Server component — missing authorization
@page "/admin/delete-user/{UserId}"

@code {
    [Parameter]
    public string UserId { get; set; }
    
    protected override async Task OnInitializedAsync()
    {
        // ⚠️ No authorization check!
        // Can be called from any circuit!
        await userService.DeleteUser(UserId);
    }
}
```

**Microsoft Threat Mitigation:** https://learn.microsoft.com/en-us/aspnet/core/blazor/security/interactive-server-side-rendering

### 2. State Manipulation

Circuit state is kept on the server, but the client can send UI events. An attacker can manipulate state by sending direct SignalR messages.

### 3. CVE-2023-35391: SignalR Information Disclosure

**CVE:** CVE-2023-35391
**CVSS:** 7.5 (High)
**Source:** https://nvd.nist.gov/vuln/detail/CVE-2023-35391

A security vulnerability in ASP.NET Core SignalR that leads to information disclosure when using the Redis backplane.

```csharp
// Vulnerable configuration
builder.AddSignalR()
    .AddStackExchangeRedis("redis_connection_string");
    // This configuration can leak sensitive data over Redis
```

### 4. CVE-2026-45591: SignalR MessagePack DoS

**CVE:** CVE-2026-45591
**CVSS:** 7.5 (High)
**Source:** https://github.com/advisories/GHSA-f8h2-vmm9-qhj6

DoS attack by sending deeply nested messages in the MessagePack hub protocol. Affects Blazor Server and all applications using SignalR.

```csharp
// 💀 Vulnerable — sending deeply nested objects with MessagePack
// An attacker can currently cause a DoS
services.AddSignalR()
    .AddMessagePackProtocol();  // Active by default
```

**Details:** https://byteiota.com/cve-2026-45591-aspnet-core-signalr-dos-patch/

## Blazor WASM Security

### 1. Trusting Client-Side Logic

In Blazor WASM, all C# code runs in the browser and **can be decompiled**.

```csharp
// 💀 DANGEROUS — Security check in WASM
public class AdminService
{
    public bool IsAdmin { get; private set; }
    
    public void CheckAdminAccess()
    {
        if (!IsAdmin)
            throw new UnauthorizedAccessException();
        // ⚠️ This check runs in WASM
        // An attacker can decompile the IL and bypass it!
    }
}
```

### 2. JS Interop Vulnerabilities

Blazor WASM calls JavaScript functions via `IJSRuntime`. Incorrect usage can lead to XSS.

```csharp
// 💀 DANGEROUS — XSS via JS Interop
var result = await JSRuntime.InvokeAsync<string>(
    "eval", $"({userInput})");  // XSS!

// ✅ SAFE — Specific JS function
var result = await JSRuntime.InvokeAsync<string>(
    "specificFunction", userInput);
```

## Blazor Framework-Specific CVEs

### CVE-2023-35390: .NET Remote Code Execution

**CVSS:** 7.8 (High) — `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`
**Affected:** .NET 6.0, .NET 7.0 (SDK / NuGet package restore)
**Source:** https://github.com/dotnet/announcements/issues/266
A **remote code execution** vulnerability (not information disclosure) triggered through `dotnet` commands / NuGet package restore. It is a .NET-wide SDK issue rather than Blazor-specific, but Blazor projects built with the affected SDK are exposed. Requires user interaction (restoring a malicious package/project).

### Server-Side Rendering (Interactive SSR) Threat Model

According to Microsoft's official threat model, the following threats are critical in Blazor Interactive SSR:

1. **Circuit connection hijack** — XSS + CSRF combination
2. **DOM manipulation** — Modifying rendered HTML
3. **Timing attacks** — Side-channel via UI events
4. **Resource exhaustion** — Server resource consumption per circuit

**Source:** https://learn.microsoft.com/en-us/aspnet/core/blazor/security/interactive-server-side-rendering

## Secure Blazor Development

```csharp
// ✅ SAFE — Server-side authorization
@page "/admin"
@attribute [Authorize(Roles = "Admin")]

@code {
    protected override async Task OnInitializedAsync()
    {
        var authState = await AuthStateProvider.GetAuthenticationStateAsync();
        var user = authState.User;
        
        if (!user.IsInRole("Admin"))
        {
            NavigationManager.NavigateTo("/access-denied");
            return;
        }
        
        // Admin operations
    }
}
```

## References

- https://learn.microsoft.com/en-us/aspnet/core/blazor/security/interactive-server-side-rendering
- https://nvd.nist.gov/vuln/detail/CVE-2023-35391
- https://github.com/advisories/GHSA-f8h2-vmm9-qhj6
- https://github.com/advisories/GHSA-j8rm-cm55-qqj6
- https://byteiota.com/cve-2026-45591-aspnet-core-signalr-dos-patch/
- https://docs.sentry.io/platforms/dotnet/guides/blazor-server/
- https://medium.com/@dgallivan23/top-security-practices-for-blazor-pwas-in-2025-788aebb763e1
