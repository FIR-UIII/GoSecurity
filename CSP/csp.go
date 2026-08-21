package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
)

// GenerateNonce создает криптографически безопасный токен
func GenerateNonce() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		panic("crypto/rand failed")
	}
	return base64.StdEncoding.EncodeToString(bytes)
}

// Шаблон HTML страницы для демонстрации
const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CSP Demo: {{.Level}}</title>
</head>
<body>
    <h1>Уровень CSP: {{.Level}}</h1>
    <p>Откройте консоль браузера (F12), чтобы увидеть, какие скрипты заблокированы.</p>

    <!-- Легитимный инлайн-скрипт (если есть nonce, он сработает, иначе зависит от политики) -->
    <script {{if .Nonce}}nonce="{{.Nonce}}"{{end}}>
        console.log("✅ Легитимный скрипт выполнен!");
        document.body.innerHTML += "<img src='x' onerror='alert(\"🚨 XSS Вектор сработал!\")'>";
    </script>

    <!-- Имитация XSS инъекции (атакующий не знает nonce) -->
    <script>
        console.warn("🚨 XSS Вектор сработал!");
        document.body.innerHTML += "<script>alert('XSS');</script>";
    </script>
</body>
</html>
`

type PageData struct {
	Level string
	Nonce string
}

func renderPage(w http.ResponseWriter, data PageData) {
	t, err := template.New("webpage").Parse(htmlTemplate)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	t.Execute(w, data)
}

func main() {
	mux := http.NewServeMux()

	// 1. Insecure CSP: Разрешено все
	mux.HandleFunc("/insecure", func(w http.ResponseWriter, r *http.Request) {
		csp := "default-src * 'unsafe-inline' 'unsafe-eval';"
		w.Header().Set("Content-Security-Policy", csp)
		renderPage(w, PageData{Level: "Insecure (Allow All)"})
	})

	// 2. Weak CSP: Уязвимый Allow-list
	mux.HandleFunc("/weak", func(w http.ResponseWriter, r *http.Request) {
		csp := "default-src 'self'; script-src 'self' 'unsafe-inline';"
		w.Header().Set("Content-Security-Policy", csp)
		renderPage(w, PageData{Level: "Weak (Self + Unsafe Inline)"})
	})

	// 3. Moderate CSP: Использование Nonce (отсекает небезопасный инлайн)
	mux.HandleFunc("/moderate", func(w http.ResponseWriter, r *http.Request) {
		nonce := GenerateNonce()
		csp := fmt.Sprintf("default-src 'self'; script-src 'self' 'nonce-%s';", nonce)

		w.Header().Set("Content-Security-Policy", csp)
		renderPage(w, PageData{Level: "Moderate (Nonce based)", Nonce: nonce})
	})

	// 4. Strict CSP: Золотой стандарт (с strict-dynamic и блокировкой object/base-uri)
	mux.HandleFunc("/strict", func(w http.ResponseWriter, r *http.Request) {
		nonce := GenerateNonce()
		csp := fmt.Sprintf(
			"object-src 'none'; base-uri 'none'; script-src 'nonce-%s' 'strict-dynamic' 'unsafe-inline' https: http:;",
			nonce,
		)

		w.Header().Set("Content-Security-Policy", csp)
		renderPage(w, PageData{Level: "Strict CSP", Nonce: nonce})
	})

	log.Println("Сервер запущен на http://localhost:8080")
	log.Println("Маршруты: /insecure, /weak, /moderate, /strict")

	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}
