package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
)

const (
	keycloakAuth  = "http://127.0.0.1:8080/realms/demo/protocol/openid-connect/auth"
	keycloakToken = "http://127.0.0.1:8080/realms/demo/protocol/openid-connect/token"
	clientID      = "demo-conf"                        // CHANGE_ME
	clientSecret  = "yrExnAIz3V6CoUz19kFPgzmjGX7sj2DG" // CHANGE_ME
	callbackURL   = "http://127.0.0.1:8000/oauth/callback"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", home)
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/oauth/callback", callback)
	mux.HandleFunc("/lab", lab)
	mux.HandleFunc("/api/me", me)
	mux.HandleFunc("/search", search)

	log.Println("RP listening on http://127.0.0.1:8000")

	if err := http.ListenAndServe(":8000", mux); err != nil {
		log.Fatal(err)
	}
}

func home(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `
		<h1>local</h1>
		<a href="/login">Login with Keycloak</a>
	`)
}

func login(w http.ResponseWriter, r *http.Request) {
	state := uuid.NewString()

	// Для демонстрации уязвимости state намеренно
	// НЕ сохраняется server-side.

	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("response_type", "code")
	params.Set("scope", "openid")
	params.Set("redirect_uri", callbackURL)
	params.Set("state", state)
	params.Set("response_mode", "query")
	// Для лаборатории можно использовать prompt=none,
	// если в браузере уже есть Keycloak SSO session.
	// params.Set("prompt", "none")

	target := keycloakAuth + "?" + params.Encode()

	http.Redirect(w, r, target, http.StatusFound)
}

func callback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")

	if code == "" {
		// Это происходит при fragment response.
		// Browser загрузит эту страницу как:
		// /oauth/callback#code=ABC
		// но сервер увидит только:
		// GET /oauth/callback
		fmt.Fprint(w, `
			<!doctype html>
			<html>
			<body>
			OAuth callback loaded.
			</body>
			</html>
			`)
		return
	}

	log.Println("======================================")
	log.Println("[RP] Authorization code received")
	log.Println(code)

	// INTENTIONALLY VULNERABLE:
	// state не проверяется.
	// В production здесь должна быть проверка:
	// state -> browser session -> OAuth transaction

	token, err := exchangeCode(code)

	if err != nil {
		log.Println("[RP] token exchange failed:", err)

		http.Error(
			w,
			"token exchange failed",
			http.StatusBadRequest,
		)
		return
	}

	log.Println("[RP] Keycloak token exchange successful")
	log.Println("[RP] token:", token)

	// Создаём application session.
	sessionID := fmt.Sprintf(
		"lab-session-%d",
		time.Now().UnixNano(),
	)

	log.Println("[RP] Creating session:", sessionID)

	http.SetCookie(w, &http.Cookie{
		Name:  "session",
		Value: sessionID,
		Path:  "/",
		// Именно это демонстрирует,
		// почему HttpOnly не спасает
		// от server-side callback атаки.
		// CORS не поможет, потому что
		// браузер не делает cross-origin
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
	})

	fmt.Fprint(w, `
		<!doctype html>
		<html>
		<body>

		<h1>OAuth login completed</h1>

		<p>Application session created.</p>
		<a href="/api/me">Check session</a>
		</body>
		</html>
		`)

	log.Println("======================================")
}

func exchangeCode(code string) (string, error) {
	data := url.Values{}

	data.Set("grant_type", "authorization_code")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", callbackURL)

	resp, err := http.PostForm(keycloakToken, data)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf(
			"Keycloak returned HTTP %d",
			resp.StatusCode,
		)
	}

	// Для лаборатории достаточно показать,
	// что token endpoint успешно ответил.
	return "TOKEN_RECEIVED", nil
}

func me(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")

	if err != nil {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(
		w,
		"Authenticated\nSession: %s\n",
		cookie.Value,
	)
}

// Лабораторная страница.
func lab(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `
<!doctype html>
<html>
<head>
	<title>Vuln page</title>
</head>

<body>

<h1>Vuln page</h1>

<p>
Paste below:
</p>

<form action="/search" method="GET">

	<textarea
		name="q"
		rows="20"
		cols="100"
		placeholder="Paste PoC here..."
	></textarea>

	<br><br>

	<button type="submit">
		Execute payload
	</button>

</form>

</body>
</html>
`)
}

func search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")

	w.Header().Set(
		"Content-Type",
		"text/html; charset=utf-8",
	)

	fmt.Fprintf(w, `<!doctype html>
<html>
<head>
	<title>Search</title>
</head>
<body>

<h1>Search result</h1>

<div>
%s
</div>

</body>
</html>`, q)
}
