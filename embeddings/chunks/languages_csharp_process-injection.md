---
source: "languages/csharp/process-injection.md"
title: "🔴 Process Injection & P/Invoke (DllImport) Risks in .NET"
category: "language-vuln"
language: "csharp"
severity: "critical"
tags: [code, csharp, explanation, language-vuln, secure, severity, vulnerability, vulnerable]
---

# 🔴 Process Injection & P/Invoke (DllImport) Risks in .NET

> **Category:** Native Interop / Code Execution / Defense Evasion Patterns  
> **Language:** C# / .NET  
> **Severity:** Critical when exposed to untrusted input or when used as malware capability  
> **CWE:** CWE-94 (Code Injection), CWE-426 (Untrusted Search Path), CWE-427 (Uncontrolled Search Path Element), CWE-114 (Process Control), CWE-78 (OS Command Injection)

## Severity / CWE

| Field | Value |
|-------|--------|
| **Severity** | 🔴 Critical (RCE, privilege escalation, AV/EDR evasion when abused) |
| **Primary CWE** | CWE-94, CWE-114, CWE-426, CWE-78 |
| **Notes** | Same APIs power legitimate profilers/debuggers **and** red-team tooling — risk is **who controls parameters** |

## Vulnerability Explanation

.NET can call Win32/Linux APIs via **P/Invoke (`DllImport`)**, **`LibraryImport`**, COM, and unsafe pointers. High-risk patterns:

### Process / memory manipulation APIs
- `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` / `NtCreateThreadEx`
- `QueueUserAPC`, `SetThreadContext`, process hollowing patterns
- Reflective loading of native shells from byte arrays

### Dangerous loading & search path
- `LoadLibrary` / `LoadLibraryEx` with attacker-controlled path → **DLL planting**
- Unquoted service paths / cwd-relative loads
- `Assembly.Load(byte[])` of untrusted managed payloads (managed “injection”)

### Unmanaged callbacks & shellcode
- Marking RWX memory and jumping to user-supplied bytes
- Mixing `Marshal.Copy` + function pointer delegates without trust boundary

### Why apps get owned
1. Plugin systems that load arbitrary native DLLs from user directories  
2. “Updater” components that download and `LoadLibrary` without signature verification  
3. Admin tools that inject into other processes for “hotpatch” without authz  
4. Deserialization / template features that eventually call native loaders  
5. AI-generated “memory trainer / game hack helper” snippets copy-pasted into production utilities  

This is **not** teaching malware development — it is documenting **how legitimate software accidentally exposes injection primitives**.

## How AI / Vibe Coding Generates This

```
Prompt: "C# function to inject a DLL into another process for debugging"
AI: full OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread sample

Prompt: "Load native plugin from user-selected path"
AI: [DllImport("kernel32")] LoadLibrary(path) with zero signature/allow-list checks

Prompt: "Run shellcode for educational purposes"
AI: VirtualAlloc + Marshal.Copy + GetDelegateForFunctionPointer
```

Models trained on offensive security blogs, pinvoke.net, and CTF write-ups will happily emit complete injection scaffolds. In a product codebase those become **RCE gadgets** if any path is user-influenced.

## Vulnerable Code

```csharp
// 💀 Attacker-controlled path → malicious DLL load
[DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
static extern IntPtr LoadLibrary(string lpFileName);

public void LoadPlugin(string userPath)
{
    // No allow-list, no Authenticode, no hash pin
    LoadLibrary(userPath);
}

// 💀 Classic remote thread injection skeleton (dangerous if args untrusted)
[DllImport("kernel32")] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
[DllImport("kernel32")] static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr addr, uint size, uint type, uint protect);
[DllImport("kernel32")] static extern bool WriteProcessMemory(IntPtr h, IntPtr addr, byte[] buf, uint size, out IntPtr written);
[DllImport("kernel32")] static extern IntPtr CreateRemoteThread(IntPtr h, IntPtr attr, uint stack, IntPtr start, IntPtr param, uint flags, out IntPtr id);

public void Inject(int pid, byte[] payload)
{
    var h = OpenProcess(0x1F0FFF, false, pid);
    var mem = VirtualAllocEx(h, IntPtr.Zero, (uint)payload.Length, 0x3000, 0x40); // RWX
    WriteProcessMemory(h, mem, payload, (uint)payload.Length, out _);
    CreateRemoteThread(h, IntPtr.Zero, 0, mem, IntPtr.Zero, 0, out _);
}

// 💀 Untrusted managed assembly load
public void LoadModule(byte[] raw) => Assembly.Load(raw); // RCE if raw is attacker-controlled
```

## Secure Fix

```csharp
// ✅ Native plugins: allow-list + integrity
public sealed class PluginLoader
{
    private static readonly HashSet<string> Allowed = new(StringComparer.OrdinalIgnoreCase)
    {
        @"C:\Program Files\MyApp\plugins\foo.dll"
    };

    public void Load(string path)
    {
        var full = Path.GetFullPath(path);
        if (!Allowed.Contains(full))
            throw new SecurityException("plugin not allow-listed");

        // Verify Authenticode / catalog or pinned SHA-256 before load
        var hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(full)));
        if (hash != ExpectedHashes[full])
            throw new SecurityException("plugin hash mismatch");

        NativeLibrary.Load(full); // prefer NativeLibrary over raw LoadLibrary when possible
    }
}

// ✅ Do not implement remote process injection in product code
// For legitimate extensibility: out-of-process sandboxed workers, RPC, AppContainer / job objects

// ✅ Managed plugins: AssemblyLoadContext + signed assemblies + sandbox
// Prefer: separate process with least privilege; never Assembly.Load(userBytes) in privileged host

// ✅ DllImport hygiene
// - Exact full path or SafeDllSearchMode assumptions documented
// - SetDllDirectory / remove cwd from search where applicable
// - Prefer LibraryImport source-generated P/Invoke on modern .NET
```

## Prevention Checklist

- [ ] Ban product features that allocate RWX and jump to byte arrays unless in a hardened, signed tooling context
- [ ] Never `LoadLibrary` / `NativeLibrary.Load` / `Assembly.Load` on attacker-influenced paths or bytes
- [ ] Allow-list plugin locations; verify signature or content hash before load
- [ ] Run extensions out-of-process with least privilege (not inside a SYSTEM service)
- [ ] Review all `DllImport`/`LibraryImport` for path, buffer length, and string marshaling bugs
- [ ] Avoid shipping “inject into game/process” utilities that require SeDebugPrivilege in enterprise software
- [ ] Enable code integrity policies (WDAC) where applicable; monitor for VirtualAllocEx+CreateRemoteThread chains
- [ ] Treat P/Invoke surfaces as **attack surface** in threat modeling and code review
- [ ] Do not paste offensive tooling samples into production repositories

## Real CVEs / Case References

Process injection is often a **technique** (MITRE ATT&CK T1055) rather than a single product CVE. Related **.NET deserialization / code execution** CVEs show how untrusted data reaches powerful sinks:

| CVE / Reference | Summary | Link |
|-----------------|---------|------|
| **CVE-2020-1147** | RCE in .NET Framework / SharePoint / Visual Studio when XML/`DataSet`/`DataTable` deserialization is abused — illustrates untrusted data → dangerous runtime behavior | https://nvd.nist.gov/vuln/detail/CVE-2020-1147 |
| **BinaryFormatter security guide** | Microsoft: BinaryFormatter is unsafe and removed in .NET 9; deserialization of untrusted data enables gadget-based code execution | https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide |
| **CVE-2024-0057** | Certificate chain validation bypass in .NET ecosystems — relevant when update/plugin download trust is crypto-dependent | https://nvd.nist.gov/vuln/detail/CVE-2024-0057 |
| **MITRE ATT&CK T1055** | Process Injection technique catalog (defense perspective) | https://attack.mitre.org/techniques/T1055/ |

Many commercial/EDR detections for C# malware focus on **P/Invoke of VirtualAllocEx / CreateRemoteThread / AmsiScanBuffer patches** — the same APIs appearing in AI-generated “helpers.”

## Vibe Coding Red Flags

| Red flag | Why |
|----------|-----|
| `CreateRemoteThread` / `NtCreateThreadEx` in app code | Injection primitive |
| `VirtualAlloc` + `0x40` (PAGE_EXECUTE_READWRITE) | Shellcode host |
| `LoadLibrary(userInput)` | DLL plant / hijack |
| `Assembly.Load(Request.Body)` | Instant RCE |
| Copy-paste from “process hollowing C#” blogs | Malware skeleton in prod |
| `SeDebugPrivilege` required “for features” | Over-privileged design |
| Unsigned plugin folders under `%TEMP%` / Downloads | Trivial persistence |
| Comments: `// educational only` still compiled into release | Ships attack code |

**Safe prompt:**  
*“Do not use process injection. For plugins: signed assemblies, allow-listed paths, out-of-process workers. Never LoadLibrary or Assembly.Load on user input.”*

---

**Severity: 🔴 Critical** when reachable by untrusted input or shipped as injectable capability.  
**CWE: CWE-94 / CWE-114 / CWE-426**
