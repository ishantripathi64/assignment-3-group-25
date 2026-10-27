# Web Server Vulnerabilities — Attack, Exploitation & Mitigation

A team project covering four categories of web server vulnerabilities. For each
category, a member implements one variant of the vulnerability, exploits it with
evidence, and then secures it.

## Team & Assignments

| Category | Member | Roll No. | Variant_chosen |
|---|---|---|---|
| SQL Injection | Shaurya Raj Mallick | IIT2024250 | Variant-1 -> Authentication bypass |
| OS Command Injection | Hardik Singh Rana | IIB2024039 | - |
| Cross-Site Scripting (XSS) | Ishan Tripathi | IIB2024038 | - |
| Cross-Site Request Forgery (CSRF) | Archee Jaiswal | IIB2024022 | - |

---

## 1. SQL Injection
**Member:** Shaurya Raj Mallick (IIT2024250)

Untrusted input is concatenated into a SQL query, letting an attacker alter the
query's structure to read, modify, or destroy data or bypass authentication.

### Mitigation hierarchy (defenses)
1. **Parameterized queries** — Prepared statements with placeholders. The primary,
   decisive fix.
2. **Safe ORM use** — ORMs parameterize for you, as long as you avoid raw
   string-built queries.
3. **Allow-list validation** — For parts placeholders can't cover (e.g. column names
   in a dynamic `ORDER BY`), accept only known values.
4. **Least privilege + safe errors** — Minimal DB rights contain the damage; generic
   error messages stop the query structure from leaking.

> **Principle:** Parameterize first; the lower layers reinforce it and cover what it cannot.

---

## 2. OS Command Injection
**Member:** Hardik Singh Rana (IIB2024039)

Untrusted input reaches a system shell, letting an attacker inject and run
arbitrary operating-system commands on the server.

### Mitigation hierarchy (defenses)
1. **Avoid the shell entirely** — Use a native library (an HTTP client, a file API)
   instead of shelling out. No command, no injection.
2. **Parameterized execution** — If you must run a program, pass it an argument
   vector with no shell to interpret metacharacters.
3. **Allow-list validation** — Accept only the characters or values you expect
   (e.g. a host-like pattern), rejecting everything else.
4. **Least privilege** — Run the service with minimal rights so a successful
   injection is contained.

> **Principle:** Strongest at the top. Lower layers reinforce the higher ones — they are not substitutes.

---

## 3. Cross-Site Scripting (XSS)
**Member:** Ishan Tripathi (IIB2024038)

Attacker-supplied script is delivered to and executed in a victim's browser in the
context of the trusted site, enabling cookie/session theft, defacement, and actions
on the user's behalf.

### Mitigation hierarchy (defenses)
1. **Output encoding + auto-escape** — Context-aware encoding; rely on a framework
   (React, Angular) that escapes by default.
2. **Sanitize rich HTML** — Where you must allow HTML, use a vetted sanitizer
   (DOMPurify); never a home-made filter.
3. **Content Security Policy (CSP)** — A strong second layer: block inline scripts
   and unauthorized sources.
4. **HttpOnly cookies + safe sinks** — HttpOnly stops cookie theft; avoid
   `innerHTML`/`eval`, use `textContent` and safe DOM APIs.

> **Principle:** Encode output first; CSP and HttpOnly are layers that contain what gets through.

---

## 4. Cross-Site Request Forgery (CSRF)
**Member:** Archee Jaiswal (IIB2024022)

A victim's authenticated browser is tricked into sending an unintended
state-changing request to a trusted site, which the site accepts because the
session cookie rides along automatically.

### Mitigation hierarchy (defenses)
1. **Anti-CSRF tokens** — A synchronizer token the attacker cannot predict. The
   primary, decisive fix.
2. **SameSite cookies** — `Lax` or `Strict` stops the cookie being sent on cross-site
   requests (on by default now).
3. **Re-auth sensitive actions** — Require a password or re-login for high-value
   actions (transfers, email change).
4. **No state-changing GET** — Use POST/PUT/DELETE for actions; a GET is trivially
   forged with an `<img>` tag.

> **Principle:** Tokens first; SameSite, re-auth and safe HTTP methods reinforce them.

---

## How to read the defense hierarchies
Each category lists its mitigations from **strongest (1) to supporting (4)**. The
top layer is the decisive fix; the layers below it reinforce the higher ones and
cover cases the primary fix cannot — they are defense-in-depth, not replacements.
