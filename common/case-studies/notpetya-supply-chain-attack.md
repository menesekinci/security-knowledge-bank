# NotPetya Supply Chain Attack — Supply Chain / Ransomware

## 📅 When Did It Happen?
June 27, 2017 (day of the attack)

## 🎯 Target System
M.E.Doc tax software in Ukraine (update mechanism was poisoned). Ultimate targets: global companies — Maersk, Merck, FedEx (TNT), Saint Gobain, WPP and thousands of organizations.

## 🔴 What Happened?
NotPetya appeared to be ransomware but was actually **a wiper malware**. Recovery was not possible. It is believed to be a Russian cyberattack against Ukraine.

Attack flow:
1. **M.E.Doc** (Ukraine's most popular tax software) automatic update system was compromised by attackers
2. Customers downloaded a file thinking it was a legitimate update — it was actually NotPetya
3. Once executed, it spread laterally across the network using EternalBlue (NSA leaked exploit)
4. The Master Boot Record (MBR) of computers was encrypted — recovery was not possible even if you paid

Maersk (the world's largest container shipping company) was among the most affected:
- **49,000** computers
- **7,000** servers
- Completely without systems for **9 days**
- They manage 25% of the world's food supply

## 🧠 Root Cause
1. **The software update mechanism was insecure** — M.E.Doc updates were distributed without code signing or integrity checks.
2. **Supply chain trust** — everyone installed the update from legitimate software without question.
3. **EternalBlue** — unpatched Windows systems accelerated network propagation.
4. **Lack of network segmentation** — the malware could spread across the entire network.

## 💥 Impact
- **$10 billion+** total global damage (White House assessment)
- **Maersk**: $300 million loss, 49,000 computers, 7,000 servers completely destroyed
- **Merck**: $870 million loss
- **FedEx (TNT)**: $400 million loss
- **80%** of systems in Ukraine affected — government, banks, airports, metro, energy companies
- Hospitals and doctors couldn't write prescriptions or access patient records
- Chernobyl nuclear plant had to switch to manual radiation monitoring

## 🔧 How Was It Fixed?
- **No kill switch existed** (unlike WannaCry) — NotPetya could not be halted globally. Researchers did find a local "vaccine": creating a read-only file at `C:\Windows\perfc` made the malware exit on that machine before encrypting it, but this protected only each computer where it was applied individually.
- Maersk rebuilt its data centers from scratch
- 4,000 new servers, 45,000 new PCs were installed
- 2,500 applications were redeployed
- Maersk luckily found an offline backup in an office in Ghana (the server hadn't been turned on due to a power outage)

## 🎓 Lessons Learned
1. **Protect your update channels** — the most common vector for supply chain attacks.
2. **Offline backups are critical** — that was the only thing that saved Maersk.
3. **Network segmentation** — malware should not be able to spread across the entire network.
4. **Patching discipline** — EternalBlue already had a patch, but many systems were not up to date.
5. **Wartime cyber threats** — NotPetya was the first major cyberattack combined with physical warfare.

## Vibe Coding Connection: How this error can be reproduced in AI code generation
When generating an automatic update system or dependency manager with AI, AI typically skips security controls (code signing, checksum verification, HTTPS requirement). A prompt like "create an auto-update mechanism" can lay the groundwork for a NotPetya-style supply chain attack. When generating update code with AI, manually add integrity checks.

## 🔗 Source / Reference (URL)
- https://www.wired.com/story/notpetya-cyberattack-ukraine-russia-code-crashed-the-world/
- https://sosintel.co.uk/case-study-maersks-response-to-notpetya-how-cybersecurity-best-practices-mitigated-a-major-cyberattack/
- https://www.sipa.columbia.edu/sites/default/files/2022-11/NotPetya%20Final.pdf
