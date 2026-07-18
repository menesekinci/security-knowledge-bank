# Kibana Timelion Prototype Pollution RCE (CVE-2019-7609) — JavaScript

## 📅 When Did It Happen?
Discovery: 2019
CVE: CVE-2019-7609
Affected versions: Kibana < 5.6.15 and < 6.6.1

## 🎯 Target System
Kibana — data visualization and exploration platform for Elasticsearch. The Timelion visualizer was targeted.

## 🔴 What Happened?
A **Prototype Pollution** attack used JavaScript's prototype chain mechanism to achieve RCE (Remote Code Execution).

What is prototype pollution?
- In JavaScript, modifying an object's `__proto__` or `constructor.prototype` property can change the behavior of all objects sharing the same prototype
- An attacker can use this mechanism to add malicious properties to `Object.prototype`
- These properties can then be used elsewhere in the application to achieve code execution

In CVE-2019-7609:
1. Kibana's Timelion visualizer did not sufficiently validate user input
2. An attacker could send a specially crafted request to pollute the prototype via `__proto__`
3. Through a chain effect (gadget chain), this led to code execution (RCE) in Node.js
4. The attacker could execute arbitrary JavaScript code and system commands on the Kibana server

According to Rapid7's Metasploit module, the attacker could be anyone with access to the Timelion application.

## 🧠 Root Cause
1. **JavaScript prototype pollution vulnerability** — user input was allowed to modify `__proto__`
2. **Insufficient input validation** — Timelion processed user input without sanitization
3. **Gadget chain** — prototype pollution combined with other functions in the application turned into RCE
4. **Nature of Node.js** — server-side JavaScript makes prototype pollution especially dangerous

## 💥 Impact
- **Full RCE** — arbitrary code execution on the Kibana server
- Attacker can execute system commands in the context of the user running Kibana
- Data leakage, lateral movement possible
- Kibana typically works with Elasticsearch — this means compromising the entire log/data infrastructure
- Metasploit exploit module was published — automating the attack

## 🔧 How Was It Fixed?
- Kibana versions 5.6.15 and 6.6.1 were released
- Input validation in Timelion was strengthened
- Prototype pollution protections were added
- Elastic published a security advisory

## 🎓 Lessons Learned
1. **Prototype pollution is a JavaScript-specific vulnerability** — it does not exist in Python, Java, Go
2. **Never use user input directly as an object property** — especially filter keys like `__proto__`, `constructor`, `prototype`
3. **Use Object.create(null)** to create pure objects (without prototype chain)
4. **Use Map** (ES6 Map) — safe against prototype pollution
5. **Input validation libraries** — use safe versions of `lodash` (`_.setWith` instead of `_.set`)

## Vibe Coding Connection: How Can This Bug Be Repeated in AI Code Generation?
AI can produce patterns vulnerable to prototype pollution, especially when generating dynamic object processing code. For example:
- `function merge(target, source) { for (let key in source) { target[key] = source[key]; } }` — AI frequently produces this pattern
- `app.post('/api/config', (req, res) => { Object.assign(config, req.body); })` — a common AI mistake
- `const settings = JSON.parse(userInput)` — then using it directly
When you ask AI to "create a config merger" or "save user settings", audit the generated code for prototype pollution.

## 🔗 References
- https://nvd.nist.gov/vuln/detail/cve-2019-7609
- https://github.com/mpgn/CVE-2019-7609
- https://www.rapid7.com/db/modules/exploit/linux/http/kibana_timelion_prototype_pollution_rce/
