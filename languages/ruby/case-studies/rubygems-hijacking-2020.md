# RubyGems Typosquatting Campaign (2020) — Ruby Supply Chain

## 📅 Incident Date
February 16–25, 2020 (700+ malicious gems uploaded; disclosed by ReversingLabs in April 2020)

## 🎯 Target System
RubyGems — the Ruby ecosystem package manager

## 🔴 What Happened?
Over **700 malicious gems** were uploaded to RubyGems in a **typosquatting** campaign.
- Attackers published intentionally misspelled versions of popular gems (e.g. `atlas-client` instead of the legitimate `atlas_client`) hoping developers would mistype the name and install the malicious copy.
- All the gems came from just two accounts: **"JimCarrey"** and **"PeterGibbons"**.
- Each rogue gem bundled a Windows executable renamed with a `.png` extension plus a Ruby script that renamed and ran it; the malware then created a VBScript and an autorun registry key for persistence.
- The core payload was a **clipboard hijacker**: it watched the clipboard, and whenever it saw something shaped like a cryptocurrency wallet address it silently swapped in an **attacker-controlled wallet address** — redirecting any crypto payment the victim was about to make.
- The typosquatted `atlas-client` gem alone reached ~2,100 downloads, roughly 30% of the legitimate gem's downloads at the time.

## Related Case: bootstrap-sass Backdoor (March 2019)
A different but famous RubyGems supply-chain incident:
- **bootstrap-sass 3.2.0.3** was published to RubyGems on **March 26, 2019** by an attacker who gained publish access.
- The malicious version added `lib/active-controller/middleware.rb`, which **Base64-decodes and `eval()`s** the value of a `___cfduid` cookie — giving an unauthenticated attacker **remote code execution** on server-side Rails apps (CVE-2019-10842).
- bootstrap-sass has 27M+ total downloads, but the malicious version (an obsolete branch) was only downloaded ~1,477 times before being pulled ~1 hour after it was reported. Version 3.2.0.4 shipped as the fix.
- Note: this was an **RCE backdoor**, not cryptomining.

## 💥 Impact
- 2020 campaign: 700+ typosquatted gems, thousands of downloads, crypto-wallet clipboard theft.
- bootstrap-sass: ~1,477 downloads of the backdoored version; unauthenticated RCE risk on affected Rails apps.
- RubyGems strengthened account security and later rolled out mandatory MFA for high-download-gem maintainers.

## 🎓 Lessons Learned
- **Type gem names carefully** — typosquats differ by a single character (`-` vs `_`).
- **Enable 2FA/MFA** on package-manager accounts — a stolen password should not be enough.
- **Pin and review dependencies**; audit new/updated gems before adding them.
- **Rotate API keys** and avoid a single long-lived publish key.

## Vibe Coding Connection
When AI generates Ruby code:
- AI recommends popular gems like "bootstrap-sass" — verify the exact name and that it is current.
- Add "check the gem's last update and download count" to the prompt.
- Be suspicious of near-miss names (`atlas-client` vs `atlas_client`).

## 🔗 Source
- https://www.reversinglabs.com/blog/mining-for-malicious-ruby-gems
- https://thehackernews.com/2020/04/rubygem-typosquatting-malware.html
- https://snyk.io/blog/malicious-remote-code-execution-backdoor-discovered-in-the-popular-bootstrap-sass-ruby-gem/
- https://github.com/advisories/GHSA-vqqv-v9m2-48p2 (CVE-2019-10842)
