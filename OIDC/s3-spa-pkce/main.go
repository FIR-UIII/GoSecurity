// Scenario 3: "SPA with code flow + PKCE"
// (https://security.lauritz-holtmann.de/post/xss-ato-gadgets/)
//
// This RP is a public client (no secret) using the authorization code flow
// with PKCE S256 - the current best practice for browser apps. PKCE stops a
// network attacker who intercepts a code. It does NOT stop an attacker who is
// already running JS in the app origin: that attacker just generates its own
// verifier/challenge pair, drives a silent prompt=none request, and redeems
// the code at the token endpoint directly (public client -> no secret needed).
//
//	go run .            -> victim RP        http://127.0.0.1:8103
//	go run ./attacker   -> attacker server  http://127.0.0.1:9103
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
)

const (
	kcBase      = "http://127.0.0.1:8080/realms/xss-ato/protocol/openid-connect"
	kcAuth      = kcBase + "/auth"
	kcToken     = kcBase + "/token"
	clientID    = "s3-spa"
	rpAddr      = "127.0.0.1:8103"
	callbackURL = "http://127.0.0.1:8103/callback"
)

var (
	mu       sync.Mutex
	sessions = map[string]string{} // sid -> pretty token response
	pending  = map[string]string{} // state -> code_verifier
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", home)
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/callback", callback)
	mux.HandleFunc("/api/me", me)
	mux.HandleFunc("/lab", lab)
	mux.HandleFunc("/search", search)

	log.Printf("[s3 RP] listening on http://%s", rpAddr)
	log.Fatal(http.ListenAndServe(rpAddr, mux))
}

func randB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func home(w http.ResponseWriter, r *http.Request) {
	sid := sidFrom(r)
	status := `<p><b>Not logged in.</b></p>`
	if sid != "" {
		status = `<p><b>Logged in.</b> <a href="/api/me">/api/me</a></p>`
	}
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8">
<h1>Scenario 3 RP - public SPA client, code flow + PKCE (S256)</h1>
%s
<ul>
  <li><a href="/login">Log in with Keycloak</a> (code + PKCE)</li>
  <li><a href="/lab">/lab</a> - reflected-XSS playground</li>
</ul>`, status)
}

func login(w http.ResponseWriter, r *http.Request) {
	state := randB64(16)
	verifier := randB64(32)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	mu.Lock()
	pending[state] = verifier
	mu.Unlock()

	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email")
	q.Set("redirect_uri", callbackURL)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	http.Redirect(w, r, kcAuth+"?"+q.Encode(), http.StatusFound)
}

func callback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" {
		fmt.Fprint(w, `<!doctype html><meta charset="utf-8"><p>callback</p>`)
		return
	}
	mu.Lock()
	verifier := pending[state]
	delete(pending, state)
	mu.Unlock()
	if verifier == "" {
		http.Error(w, "unknown state", http.StatusBadRequest)
		return
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientID)
	form.Set("code", code)
	form.Set("redirect_uri", callbackURL)
	form.Set("code_verifier", verifier)

	resp, err := http.PostForm(kcToken, form)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		http.Error(w, "token endpoint: "+resp.Status+"\n"+string(body), http.StatusBadGateway)
		return
	}

	var m map[string]any
	_ = json.Unmarshal(body, &m)
	for _, k := range []string{"access_token", "id_token", "refresh_token"} {
		if v, ok := m[k].(string); ok && len(v) > 32 {
			m[k] = v[:32] + "..."
		}
	}
	nice, _ := json.MarshalIndent(m, "", "  ")

	sid := randB64(18)
	mu.Lock()
	sessions[sid] = string(nice)
	mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, Path: "/", HttpOnly: true, MaxAge: 3600})
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><h1>Logged in</h1><pre>%s</pre>`, string(nice))
}

func me(w http.ResponseWriter, r *http.Request) {
	sid := sidFrom(r)
	mu.Lock()
	tok, ok := sessions[sid]
	mu.Unlock()
	if !ok {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "session %s\n\n%s\n", sid, tok)
}

func lab(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<!doctype html><meta charset="utf-8">
<h1>/search - reflected XSS</h1>
<form action="/search" method="GET">
  <textarea name="q" rows="6" cols="90" placeholder="paste PoC here"></textarea><br>
  <button>reflect</button>
</form>`)
}

// INTENTIONALLY VULNERABLE: q written into HTML verbatim, no CSP.
func search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><h1>Results</h1><div>%s</div>`, q)
}

func sidFrom(r *http.Request) string {
	c, err := r.Cookie("sid")
	if err != nil {
		return ""
	}
	mu.Lock()
	_, ok := sessions[c.Value]
	mu.Unlock()
	if ok {
		return c.Value
	}
	return ""
}
