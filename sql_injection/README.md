# SQL Injection — Authentication Bypass Demo

IT-30001 Cyber Security · Module 3 · Web Server Security

A single Express app with two login handlers — a **vulnerable** one (string-built
query) and a **patched** one (parameterized query + allow-list) — so the same
attack can be shown succeeding, then failing.

## Run it

Requires Node.js 18+ (`better-sqlite3` compiles a native module on install, so
you need build tools: on Windows they come with Node's installer, on macOS
`xcode-select --install`, on Linux `build-essential` + `python3`).

```bash
cd sqli-auth-bypass-demo
npm install
npm start
```

Then open **http://localhost:3000**. The database lives in memory and is
re-seeded every time you start the server, so nothing is persisted.

Seeded accounts:

| username | password        | role          |
|----------|-----------------|---------------|
| admin    | SuperSecret123  | administrator |
| asha     | s3cret          | user          |

## The exploit (authentication bypass)

In **Vulnerable mode**, log in with **no valid password**:

- username `admin'--`  + any password → logs in as **admin**
- username `-' OR '1'='1'-` + any password → logs in as the first user

The page prints the exact query the database ran, so you can see why.

Same thing from the command line (handy for the viva):

```bash
curl -s http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"user":"admin'\''--","pass":"wrong","mode":"vulnerable"}'
```

## The fix

Switch to **Patched mode** and run the identical payload — it now returns
**Invalid credentials**. The `'` is treated as a literal character in the
username, so no row matches, and the allow-list rejects it before the query even
runs.

## Where each deliverable lives

| Deliverable | Location |
|-------------|----------|
| (a) Vulnerable implementation | `loginVulnerable()` in `server.js` — the concatenated `sql` string |
| (b) Working exploit | `admin'--` / `' OR '1'='1'--` payloads above |
| (c) Root cause | input concatenated into the query, so `'` is parsed as SQL syntax, not data |
| (d) Mitigation implemented | `loginSafe()` in `server.js` — `?` placeholders + allow-list |
| (e) Other mitigations | see `VIDEO_SCRIPT.md`, section (e) |

## Note for the viva

Passwords are stored in plaintext here only to keep the demo legible. Even if
they were bcrypt-hashed, `admin'--` would still work — the injection comments out
the password check entirely, so the attack never compares a password at all.
That is the point worth stressing: auth bypass defeats login without cracking
anything.
