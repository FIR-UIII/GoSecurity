# Scenario 3 — SPA, code flow + PKCE (S256)

Based on <https://security.lauritz-holtmann.de/post/xss-ato-gadgets/> (gadget 3).

## Idea

The recommended setup for browser apps: **public** client, authorization code
flow, **PKCE S256 enforced** by the IdP, implicit flow disabled. PKCE defeats a
network attacker who steals a `code` in transit.

It does **not** defeat an attacker who already runs JavaScript in the app
origin. That attacker owns *both* halves of the PKCE exchange:

```js
verifier  = random()
challenge = base64url(sha256(verifier))

open  https://IdP/auth?client_id=s3-spa
                       &response_type=code
                       &response_mode=fragment
                       &code_challenge=<challenge>&code_challenge_method=S256
                       &redirect_uri=http://127.0.0.1:8103/callback
                       &prompt=none

code = new URLSearchParams(iframe.location.hash).get("code")

POST https://IdP/token   grant_type=authorization_code
                         client_id=s3-spa            (public — no secret)
                         code=<code>
                         code_verifier=<verifier>    (the attacker's own)
```

The token endpoint returns the victim's `access_token` directly to the
injected script (CORS is allowed for the SPA origin), which exfiltrates it.
127.0.0.1 is a secure context, so `crypto.subtle` is available for the
challenge.

## Layout

| file | port | role |
|------|------|------|
| `main.go`         | 8103 | victim RP: public client, real code+PKCE login; reflected-XSS `/search` |
| `attacker/main.go`| 9103 | payload does the whole flow in-browser, exfiltrates the token, calls `userinfo` |

## Run

```sh
cd s3-spa-pkce
go run .            # RP        -> http://127.0.0.1:8103
go run ./attacker   # attacker  -> http://127.0.0.1:9103
```

1. Sign in once at <http://127.0.0.1:8103/login> as `victim` / `victim`.
   (Login fails with "Invalid username or password"? Run `bash ../keycloak/setup.sh`.)
2. Open <http://127.0.0.1:9103/> and follow the reflected-XSS link.
3. Attacker console / <http://127.0.0.1:9103/loot> shows the token response
   and `userinfo` → `preferred_username: victim`.

## Fix

PKCE is necessary but not sufficient here. The OAuth 2.0 "Browser-Based Apps"
BCP recommends keeping tokens out of reach of page JS:

* a **token-mediating backend** (BFF) that holds the tokens and exposes only a
  same-site session cookie, or
* a **service worker** that owns the tokens and attaches them to requests.
* Plus the usual: output encoding, strict CSP, disable `prompt=none` if the
  app doesn't need silent renewal.
