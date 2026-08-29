// Scenario 2: "Confidential client without PKCE"
// (https://security.lauritz-holtmann.de/post/xss-ato-gadgets/)
//
// This RP is a classic server-side web app: a CONFIDENTIAL client, code flow,
// client secret kept on the backend. It does NOT use PKCE, and - the bug that
// makes the gadget land - it does not bind the `state` value to the browser
// session, so any `code` presented to /callback gets redeemed.
//
// An XSS in this origin opens a silent `response_mode=fragment` code request
// (prompt=none). The victim's `code` lands in the fragment of a page on THIS
// origin. The attacker then performs "authorization code injection": feed that
// code to /callback and the backend redeems it (with its own secret) and hands
// back a session cookie for the victim.
//
//	go run .            -> victim RP        http://127.0.0.1:8102
//	go run ./attacker   -> attacker server  http://127.0.0.1:9102
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

const (
	kcBase       = "http://127.0.0.1:8080/realms/xss-ato/protocol/openid-connect"
	kcAuth       = kcBase + "/auth"
	kcToken      = kcBase + "/token"
	clientID     = "s2-confidential"
	clientSecret = "s2-confidential-secret-0000"
	rpAddr       = "127.0.0.1:8102"
	callbackURL  = "http://127.0.0.1:8102/callback"
)

type session struct {
	User   string
	Tokens string
}

var (
	mu       sync.Mutex
	sessions = map[string]session{}
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", home)
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/callback", callback)
	mux.HandleFunc("/api/me", me)
	mux.HandleFunc("/lab", lab)
	mux.HandleFunc("/search", search)

	log.Printf("[s2 RP] listening on http://%s", rpAddr)
	log.Fatal(http.ListenAndServe(rpAddr, mux))
}

func randB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func home(w http.ResponseWriter, r *http.Request) {
	s, ok := lookup(r)
	status := `<p><b>Not logged in.</b></p>`
	if ok {
		status = fmt.Sprintf(`<p><b>Logged in as %s.</b> <a href="/api/me">/api/me</a></p>`, s.User)
	}
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8">
<h1>Scenario 2 RP - confidential client, code flow, no PKCE</h1>
%s
<ul>
  <li><a href="/login">Log in with Keycloak</a></li>
  <li><a href="/lab">/lab</a> - reflected-XSS playground</li>
</ul>`, status)
}

func login(w http.ResponseWriter, r *http.Request) {
	// A state value is generated but - INTENTIONALLY VULNERABLE - it is never
	// stored or checked in /callback. That is what lets an injected code be
	// redeemed in a browser context it was not issued for.
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email")
	q.Set("redirect_uri", callbackURL)
	q.Set("state", randB64(16))
	http.Redirect(w, r, kcAuth+"?"+q.Encode(), http.StatusFound)
}

func callback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		// fragment response lands here with no query; keep body framable
		fmt.Fprint(w, `<!doctype html><meta charset="utf-8"><p>callback</p>`)
		return
	}

	// NOTE: no `state` verification here. See login().
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", callbackURL)

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

	var tr struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal(body, &tr)
	user := jwtClaim(tr.IDToken, "preferred_username")

	sid := randB64(18)
	mu.Lock()
	sessions[sid] = session{
		User: user,
		Tokens: fmt.Sprintf("access_token %s...\nid_token %s...\nrefresh_token %s...",
			cut(tr.AccessToken), cut(tr.IDToken), cut(tr.RefreshToken)),
	}
	mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, Path: "/", HttpOnly: true, MaxAge: 3600})

	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8">
<h1>Logged in as %s</h1><pre>%s</pre><a href="/">home</a>`, user, sessions[sid].Tokens)
}

func me(w http.ResponseWriter, r *http.Request) {
	s, ok := lookup(r)
	if !ok {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "logged in as: %s\n\n%s\n", s.User, s.Tokens)
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

func lookup(r *http.Request) (session, bool) {
	c, err := r.Cookie("sid")
	if err != nil {
		return session{}, false
	}
	mu.Lock()
	defer mu.Unlock()
	s, ok := sessions[c.Value]
	return s, ok
}

func cut(s string) string {
	if len(s) > 24 {
		return s[:24]
	}
	return s
}

// jwtClaim pulls one string claim out of a JWT payload without verifying it
// (lab only - never trust an unverified token in real code).
func jwtClaim(jwt, name string) string {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return "?"
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "?"
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return "?"
	}
	if v, ok := m[name].(string); ok {
		return v
	}
	return "?"
}
