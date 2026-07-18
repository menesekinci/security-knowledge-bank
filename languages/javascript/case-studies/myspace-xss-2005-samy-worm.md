# MySpace / Samy XSS Worm (2005) — JavaScript DOM-based XSS

## 📅 When Did It Happen?
2005 — Samy Kamkar's MySpace XSS worm

## 🎯 Target System
MySpace (the largest social network of 2005) — JavaScript filtering system

## 🔴 What Happened?
**Samy (Samy Kamkar)** found a technique to bypass MySpace's XSS protection.
- MySpace banned JavaScript in user profiles (filtered script tags)
- Samy hid JavaScript inside CSS:
```javascript
<div id="mycode" expr="alert('haha')" style="background:url('javascript:eval(alert(1))')">
```
- He added this code to his profile. Every visitor automatically added Samy as a friend and copied the code to their own profile
- **Over 1 million users affected in under ~20 hours** (the fastest-spreading worm at the time)
- MySpace was completely shut down

A more recent XSS case:
**British Airways (2018)**: 380,000 customers' credit card information was stolen via MageCart JavaScript.
- JS injected into the payment page sent card details to the attacker
- Done via a modified first-party JavaScript file (the site's own Modernizr script)
- £20 million ICO fine (~$26M)

## 💥 Impact
- Samy worm: MySpace down for hours, Samy questioned by the FBI
- British Airways: 380K credit cards stolen, £20 million ICO fine (~$26M)
- A milestone demonstrating how devastating XSS can be

## 🎓 Lessons Learned
- **Input sanitization** is not enough — output encoding is also required
- **Use CSP (Content Security Policy)** — block inline JS
- **Verify 3rd party JS libraries** with SRI (Subresource Integrity)
- **Start CSP in report-only mode**, then switch to enforce

## Vibe Coding Connection
When AI generates JavaScript code:
- It may suggest DOM manipulations like `innerHTML`, `document.write`
- It does not question the use of `dangerouslySetInnerHTML` (React)
- It forgets to add CSP headers
- Add "use CSP" and "sanitize with DOMPurify" to the prompt

## 🔗 References
- https://samy.pl/myspace/ (Samy's own account)
- https://www.bbc.com/news/technology-44968100 (British Airways)
