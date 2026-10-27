// =============================================================
//  SQL Injection - Authentication Bypass demo
//  IT-30001 Cyber Security - Module 3 - Web Server Security
//
//  One server, two login handlers:
//    POST /login  with  mode = "vulnerable"  -> the FLAW   (deliverable a)
//    POST /login  with  mode = "safe"        -> the FIX    (deliverable d)
//
//  Run:  npm install  &&  npm start
//  Open: http://localhost:3000
// =============================================================

const express = require("express");
const Database = require("better-sqlite3");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ---- in-memory database, re-seeded on every startup --------------------
const db = new Database(":memory:");
db.exec(`
  CREATE TABLE users (
    id       INTEGER PRIMARY KEY,
    username TEXT,
    password TEXT,          -- plaintext here ONLY to keep the demo readable
    role     TEXT
  );
  INSERT INTO users (username, password, role) VALUES
    ('admin', 'SuperSecret123', 'administrator'),
    ('asha',  's3cret',         'user');
`);

// =============================================================
//  (a) VULNERABLE handler  -  user input concatenated into SQL
// =============================================================
function loginVulnerable(user, pass) {
  // The flaw: the submitted values are glued straight into the query text,
  // so the database parses them as SQL, not as data.
  const sql =
    "SELECT * FROM users WHERE username = '" + user +
    "' AND password = '" + pass + "'";

  console.log("\n[VULNERABLE] query sent to DB:\n  " + sql);

  const rows = db.prepare(sql).all();   // input is part of the query string
  return { rows, sql };
}

// =============================================================
//  (d) PATCHED handler  -  parameterized query + allow-list
// =============================================================
function loginSafe(user, pass) {
  // Secondary layer: reject anything that is not a plain username.
  if (!/^[A-Za-z0-9_]+$/.test(user)) {
    return { rows: [], sql: "(rejected by allow-list before any query)" };
  }

  // Primary fix: the query structure is fixed up front with ? placeholders.
  // The values travel separately and are never parsed as SQL.
  const sql = "SELECT * FROM users WHERE username = ? AND password = ?";

  console.log("\n[SAFE] parameterized query:\n  " + sql +
              "\n  values: [" + user + ", " + pass + "]");

  const rows = db.prepare(sql).all(user, pass);
  return { rows, sql };
}

// ---- the login route both the form and curl talk to --------------------
app.post("/login", (req, res) => {
  const user = req.body.user ?? "";
  const pass = req.body.pass ?? "";
  const mode = req.body.mode === "safe" ? "safe" : "vulnerable";

  const { rows, sql } =
    mode === "safe" ? loginSafe(user, pass) : loginVulnerable(user, pass);

  if (rows.length > 0) {
    res.json({
      ok: true,
      mode,
      message: "Login successful - welcome, " + rows[0].username +
               " (" + rows[0].role + ")",
      executedQuery: sql
    });
  } else {
    res.json({
      ok: false,
      mode,
      message: "Invalid credentials",
      executedQuery: sql
    });
  }
});

// ---- minimal front-end so the attack can be shown in a browser ---------
app.get("/", (_req, res) => res.type("html").send(PAGE));

const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SQLi Auth-Bypass Demo</title>
<style>
  :root { --bg:#0f1e3d; --card:#ffffff; --ink:#0f1e3d; --accent:#d4a017;
          --ok:#1b7f3b; --bad:#b23b2e; --muted:#5b6b86; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:system-ui,Segoe UI,Roboto,sans-serif;
         background:var(--bg); color:var(--ink); display:flex;
         justify-content:center; padding:32px 16px; }
  .card { background:var(--card); width:100%; max-width:560px; border-radius:14px;
          padding:28px; box-shadow:0 18px 50px rgba(0,0,0,.35); }
  h1 { font-size:20px; margin:0 0 4px; }
  p.sub { margin:0 0 20px; color:var(--muted); font-size:14px; }
  label { display:block; font-size:13px; font-weight:600; margin:14px 0 6px; }
  input { width:100%; padding:11px 12px; border:1px solid #cdd4e0; border-radius:8px;
          font-size:15px; font-family:ui-monospace,Menlo,Consolas,monospace; }
  .modes { display:flex; gap:10px; margin:22px 0 6px; }
  button { flex:1; padding:12px; border:0; border-radius:8px; font-size:14px;
           font-weight:700; cursor:pointer; color:#fff; }
  .vuln { background:var(--bad); }
  .safe { background:var(--ok); }
  #out { margin-top:20px; padding:14px 16px; border-radius:8px; font-size:14px;
         display:none; }
  #out.ok  { background:#e7f5ec; color:var(--ok);  border:1px solid #bfe3cc; }
  #out.bad { background:#fdecea; color:var(--bad); border:1px solid #f3c7c1; }
  #out .msg { font-weight:700; }
  #out code { display:block; margin-top:10px; padding:10px; background:#0f1e3d;
              color:#e9edf5; border-radius:6px; font-size:12px; white-space:pre-wrap;
              word-break:break-all; font-family:ui-monospace,Menlo,Consolas,monospace; }
  .hint { margin-top:18px; font-size:12px; color:var(--muted); line-height:1.5; }
  .hint code { background:#eef1f6; padding:1px 5px; border-radius:4px; }
</style>
</head>
<body>
  <div class="card">
    <h1>Secure Portal &mdash; Login</h1>
    <p class="sub">IT-30001 &middot; Module 3 &middot; SQL injection authentication-bypass demo</p>

    <label>Username</label>
    <input id="user" value="" placeholder="e.g. asha">
    <label>Password</label>
    <input id="pass" value="" placeholder="password">

    <div class="modes">
      <button class="vuln" onclick="go('vulnerable')">Login &mdash; Vulnerable mode</button>
      <button class="safe" onclick="go('safe')">Login &mdash; Patched mode</button>
    </div>

    <div id="out"></div>

    <div class="hint">
      Valid account: <code>asha</code> / <code>s3cret</code>.<br>
      Try the bypass in <b>Vulnerable mode</b>: username <code>admin'--</code> with any password,
      or username <code>' OR '1'='1'--</code> with any password. Then run the same payload in
      <b>Patched mode</b> and watch it fail.
    </div>
  </div>

<script>
async function go(mode){
  const r = await fetch("/login", {
    method:"POST",
    headers:{ "Content-Type":"application/json" },
    body: JSON.stringify({
      user: document.getElementById("user").value,
      pass: document.getElementById("pass").value,
      mode
    })
  });
  const d = await r.json();
  const out = document.getElementById("out");
  out.style.display = "block";
  out.className = d.ok ? "ok" : "bad";
  out.innerHTML = '<span class="msg">[' + d.mode.toUpperCase() + '] ' + d.message +
                  '</span><code>' + d.executedQuery.replace(/</g,"&lt;") + '</code>';
}
</script>
</body>
</html>`;

app.listen(3000, () =>
  console.log("SQLi demo running:  http://localhost:3000")
);
