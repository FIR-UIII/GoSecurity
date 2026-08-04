package main

import (
	"io"
	"net/http"
)

// XSS http://localhost:8080/?param1=<script>alert(1)</script>. Content-Type=text/plain text/html - vulnerable to XSS attack
func handler(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, r.URL.Query().Get("param1"))
}
func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8080", nil)
}
