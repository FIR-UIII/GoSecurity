package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
)

type User struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Role     string `json:"role"`
	Email    string `json:"email"`
	Secret   string `json:"secret"`
	Password string `json:"-"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var users = []User{
	{ID: 1, Name: "Art", Role: "admin", Email: "art@example.local", Secret: "admin budget and notes", Password: "admin123"},
	{ID: 2, Name: "Bob", Role: "user", Email: "bob@example.local", Secret: "customer export and draft", Password: "bob123"},
	{ID: 3, Name: "Mia", Role: "manager", Email: "mia@example.local", Secret: "internal roadmap", Password: "mia123"},
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-User-ID")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func findUserByID(id int) (*User, bool) {
	for i := range users {
		if users[i].ID == id {
			return &users[i], true
		}
	}
	return nil, false
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
	publicUsers := make([]map[string]any, 0, len(users))
	for _, user := range users {
		publicUsers = append(publicUsers, map[string]any{
			"id":    user.ID,
			"name":  user.Name,
			"role":  user.Role,
			"email": user.Email,
		})
	}
	writeJSON(w, http.StatusOK, publicUsers)
}

func userDetailHandler(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/users/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user id"})
		return
	}

	user, ok := findUserByID(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}

	// Intentional weakness: this endpoint returns sensitive profile data without authorization.
	writeJSON(w, http.StatusOK, user)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}

	// Intentional weakness: overly simple login logic for training.
	for _, user := range users {
		if user.Name == req.Username && (req.Password == user.Password || req.Password == "password" || req.Password == "123456") {
			writeJSON(w, http.StatusOK, map[string]any{
				"message": "login accepted",
				"user": map[string]any{
					"id":   user.ID,
					"name": user.Name,
					"role": user.Role,
				},
			})
			return
		}
	}

	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	// Intentional weakness: trust a caller-controlled header instead of session state.
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing X-User-ID header"})
		return
	}

	id, err := strconv.Atoi(userID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid X-User-ID header"})
		return
	}

	user, ok := findUserByID(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "profile not found"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":     user.ID,
		"name":   user.Name,
		"role":   user.Role,
		"email":  user.Email,
		"secret": user.Secret,
	})
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", healthHandler)
	mux.HandleFunc("/api/login", loginHandler)
	mux.HandleFunc("/api/profile", profileHandler)
	mux.HandleFunc("/api/users", usersHandler)
	mux.HandleFunc("/api/users/", userDetailHandler)

	log.Println("vulnerable training API listening on :8080")
	if err := http.ListenAndServe(":8080", withCORS(mux)); err != nil {
		log.Fatal(err)
	}
}
