# 🟡 Unity Game Security (C# / IL2CPP)

> **Category:** Client Trust / Reverse Engineering / Game & Mobile Hardening  
> **Language:** C# (Unity), IL2CPP native  
> **Severity:** Medium to High (cheating, economy fraud, credential theft, account takeover)  
> **CWE:** CWE-602 (Client-Side Enforcement of Server-Side Security), CWE-311 (Missing Encryption of Sensitive Data), CWE-798 (Hard-coded Credentials), CWE-922 (Insecure Storage of Sensitive Information)

## Severity / CWE

| Field | Value |
|-------|--------|
| **Severity** | 🟠 Medium–High (depends on economy / auth / multiplayer model) |
| **Primary CWE** | CWE-602, CWE-311, CWE-798, CWE-922, CWE-353 (Missing Support for Integrity Check) |
| **OWASP Mobile** | M2 Insecure Data Storage, M3 Insecure Communication, M7 Insufficient Binary Protections |

## Vulnerability Explanation

Unity ships games as **untrusted clients**. Attackers use:

- **dnSpy / ILSpy** on Mono builds; **Il2CppDumper + IDA/Ghidra** on IL2CPP
- **Frida / GameGuardian / Cheat Engine** for memory edits (gold, HP, flags)
- **SSL pinning bypass** on mobile Unity apps (Frida unpinning scripts target common Unity networking stacks)
- **Protocol reimplementation** after dumping protobuf/JSON message formats
- **Asset bundle / Addressable** inspection for keys, endpoints, feature flags

Common failure modes:

1. **Authoritative logic on client** — damage, currency, inventory, match outcomes computed only in C# and trusted by server.
2. **Secrets in assemblies** — API keys, Firebase/Google service accounts, HMAC secrets, premium unlock keys in `Resources` or `ScriptableObject` assets.
3. **Insecure storage** — PlayerPrefs for tokens, save files with plaintext gold/levels, unencrypted local SQLite.
4. **Weak transport** — HTTP for login/payments, disabled certificate validation “for debugging,” no pinning with rotation plan.
5. **Debug / Editor leftovers** — `Debug.isDebugBuild` cheats, backdoors, verbose logs of session tokens in production builds.
6. **Moddable multiplayer** — peer-hosted games without server-side validation → speed hacks, aimbots, economy duplication.

IL2CPP raises the bar vs Mono but **does not stop** reverse engineering; it only slows casual attackers.

## How AI / Vibe Coding Generates This

```
Prompt: "Unity multiplayer shop: buy item with coins"
AI: client checks coins, subtracts locally, sends BuyItem(itemId) to server;
    server trusts client balance → free items after memory edit

Prompt: "Save player progress"
AI: PlayerPrefs.SetString("token", jwt); PlayerPrefs.SetInt("gold", gold);

Prompt: "Call backend API"
AI: hardcoded base URL + API key in a C# const; HttpClient without pinning
```

AI optimizes for **playable demos**, not adversarial multiplayer. Tutorial and Asset Store patterns reinforce client-side authority and PlayerPrefs “persistence.”

## Vulnerable Code

```csharp
// 💀 Client-authoritative economy
public class ShopClient : MonoBehaviour
{
    public int coins;
    public void Buy(string itemId, int price)
    {
        if (coins < price) return;
        coins -= price; // memory-editable
        PlayerPrefs.SetInt("coins", coins);
        StartCoroutine(Api.Post("/buy", new { itemId })); // server does not re-check balance
    }
}

// 💀 Secrets in client binary
public static class Config
{
    public const string ApiKey = "sk_live_unity_xxx";
    public const string HmacSecret = "supersecret";
}

// 💀 Token in PlayerPrefs (rooted device / shared prefs dump)
PlayerPrefs.SetString("session", jwt);

// 💀 Dev TLS bypass left in build
#if !UNITY_EDITOR
// still wrong if this ships:
ServicePointManager.ServerCertificateValidationCallback = (_,__,___,____) => true;
#endif
```

## Secure Fix

```csharp
// ✅ Server-authoritative purchase
// Client only requests intent; server loads balance from DB, validates price, deducts atomically
[HttpPost("/buy")]
public async Task<IActionResult> Buy([FromBody] BuyRequest req, ClaimsPrincipal user)
{
    var userId = user.GetUserId();
    await using var tx = await _db.Database.BeginTransactionAsync();
    var account = await _db.Accounts.FirstAsync(a => a.Id == userId);
    var item = await _db.Items.FirstAsync(i => i.Id == req.ItemId);
    if (account.Coins < item.Price) return Conflict("insufficient_funds");
    account.Coins -= item.Price;
    _db.Inventory.Add(new InventoryRow { UserId = userId, ItemId = item.Id });
    await _db.SaveChangesAsync();
    await tx.CommitAsync();
    return Ok(new { balance = account.Coins });
}

// ✅ No long-lived secrets in client — use short-lived session tokens from your backend
// ✅ Sensitive local data: platform secure storage (Android Keystore / iOS Keychain plugins), not PlayerPrefs
// ✅ Release: IL2CPP + stripped symbols + anti-tamper where threat model requires; still never trust client math
// ✅ Certificate pinning with backup pins + forced update path when pins rotate
```

Architectural rule: **anything valuable (currency, loot, match result, ban state) is decided on a trusted server.** Client is a renderer + input device.

## Prevention Checklist

- [ ] All economy, combat resolution, matchmaking outcomes server-validated
- [ ] No API keys / HMAC secrets / private Firebase keys in client builds (scan CI for `sk_live`, service accounts)
- [ ] Session tokens in platform secure storage; short TTL; refresh rotation
- [ ] TLS everywhere; no permanent cert validation bypass; pin carefully with rotation
- [ ] Production builds: IL2CPP, disable debug consoles/cheats, strip logging of secrets
- [ ] Anti-cheat as defense-in-depth only — never sole control for economy
- [ ] Save files: integrity MAC or encrypt with keys not solely on device if offline abuse matters
- [ ] Threat model docs: what a rooted device / PC trainer can do vs must not affect global state
- [ ] Regular binary review / secret scanning of APK/IPA/Standalone builds

## Real CVEs / Case References

Unity-specific public CVEs are often **engine/editor/build-pipeline** issues rather than “C# shop script” bugs; game security failures more often appear as **incident write-ups** and **mobile pinning/RE** research:

| Reference | Summary | Link |
|-----------|---------|------|
| **Unity security / hardening guidance** | Engine does not provide inherent RE or memory-edit protection; multiplayer must be hardened server-side | Vendor/security vendor analyses (e.g. industry Unity security overviews) |
| **IL2CPP RE research** | Public reverse-engineering of Unity Android games (Smali + global-metadata) demonstrates extractable logic/strings | https://palant.info/2021/02/18/reverse-engineering-a-unity-based-android-game/ |
| **SSL pinning bypass tooling** | Frida unpinning ecosystems routinely target mobile games including Unity stacks | Community tooling (e.g. httptoolkit frida-interception issues discussing Unity apps) |
| **Related .NET crypto/PKI** | Incomplete cert validation patterns in .NET stacks — same class of mistake in Unity networking wrappers | https://nvd.nist.gov/vuln/detail/CVE-2024-0057 |

Treat “no Unity CVE for my shop bug” as normal: **CWE-602 is design**, not always a CVE ID.

## Vibe Coding Red Flags

| Red flag | Risk |
|----------|------|
| `if (coins >= price) coins -= price` only on client | Infinite money trainers |
| `PlayerPrefs` for JWT / payment state | Token theft on shared/rooted devices |
| `const string ApiKey` / secrets in `ScriptableObject` | Extracted in minutes |
| “Offline-first multiplayer” without CRDT/server authority | Duping / desync exploits |
| Debug menu enabled with `// remove later` | Shipped god-mode |
| Trusting client `damageDealt` / `isHeadshot` | Aimbot economy |
| HTTP login endpoints in production scenes | Credential sniffing |
| Asset Store “anti-cheat” as only protection | False confidence |

**Prompt pattern:**  
*“Server is authoritative for inventory, currency, and match results. Client never holds long-lived API secrets. Use secure storage for session tokens. Assume IL2CPP binaries will be dumped.”*

---

**Severity: 🟠 Medium–High** — fraud, cheating, account takeover, brand damage.  
**CWE: CWE-602 / CWE-311 / CWE-798 / CWE-922**
