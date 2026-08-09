package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type User struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// must satisfy interface http.Handler -> ServeHTTP(ResponseWriter, *Request)
func usersHandler(w http.ResponseWriter, r *http.Request) {
	users := []User{
		{ID: 1, Name: "Art"},
		{ID: 2, Name: "Bob"},
	}
	log.Printf("received request from %v", r.RemoteAddr)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
	// here no return, because we want to continue processing the request in the next handler
}

// authMiddleware is a simple middleware that checks for a specific header value for authentication.
// logic http.Handler -> authMiddleware -> http.Handler
// this func calls middleware or decorator pattern, which is a common pattern in Go for wrapping handlers with additional functionality.
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auth-Token") != "secret" { // simple trivial check for demonstration purposes
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	http.Handle("/api/users", authMiddleware(http.HandlerFunc(usersHandler)))
	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
