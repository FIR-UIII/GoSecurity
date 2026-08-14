package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strings"

	_ "modernc.org/sqlite"
)

var db *sql.DB

func main() {
	var err error

	db, err = sql.Open("sqlite", "file:lab.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	initDB()

	// --------------------------------------------------
	// SELECT
	// --------------------------------------------------

	http.HandleFunc("/01/concat", vulnConcat)
	http.HandleFunc("/02/sprintf", vulnSprintf)
	http.HandleFunc("/03/builder", vulnBuilder)
	http.HandleFunc("/04/fprintf", vulnFprintf)
	http.HandleFunc("/05/in", vulnIN)
	http.HandleFunc("/06/like", vulnLIKE)

	// --------------------------------------------------
	// UPDATE / DELETE / INSERT
	// --------------------------------------------------

	http.HandleFunc("/07/update", vulnUPDATE)
	http.HandleFunc("/08/delete", vulnDELETE)
	http.HandleFunc("/09/insert", vulnINSERT)

	// --------------------------------------------------
	// Dynamic SQL
	// --------------------------------------------------

	http.HandleFunc("/10/order", vulnORDER)
	http.HandleFunc("/11/limit", vulnLIMIT)
	http.HandleFunc("/12/where", vulnWHERE)

	// --------------------------------------------------
	// Prepare incorrectly
	// --------------------------------------------------

	http.HandleFunc("/13/fake-prepare", vulnFakePrepare)

	// --------------------------------------------------
	// Second-order SQLi
	// --------------------------------------------------

	http.HandleFunc("/14/store", storeSecondOrder)
	http.HandleFunc("/14/use", useSecondOrder)

	// --------------------------------------------------
	// Safe implementations
	// --------------------------------------------------

	http.HandleFunc("/safe/select", safeSelect)
	http.HandleFunc("/safe/update", safeUpdate)
	http.HandleFunc("/safe/order", safeOrder)

	log.Println("SQLi lab listening on http://localhost:8080")

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func initDB() {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY,
			name TEXT,
			role TEXT,
			email TEXT
		)
	`)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`DELETE FROM users`)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
		INSERT INTO users(name, role, email) VALUES
			('alice', 'user', 'alice@example.com'),
			('bob', 'admin', 'bob@example.com'),
			('charlie', 'user', 'charlie@example.com')
	`)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS saved_filters (
			id INTEGER PRIMARY KEY,
			filter TEXT
		)
	`)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`DELETE FROM saved_filters`)
	if err != nil {
		log.Fatal(err)
	}
}

// ======================================================
// 01. String concatenation
// ======================================================

func vulnConcat(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")

	query := "SELECT id, name, role FROM users WHERE name = '" +
		name +
		"'"

	logQuery(query)

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	defer rows.Close()

	writeUsers(w, rows)
}

// ======================================================
// 02. fmt.Sprintf
// ======================================================

func vulnSprintf(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")

	query := fmt.Sprintf(
		"SELECT id, name, role FROM users WHERE name = '%s'",
		name,
	)

	logQuery(query)

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	defer rows.Close()

	writeUsers(w, rows)
}

// ======================================================
// 03. strings.Builder
// ======================================================

func vulnBuilder(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")

	var query strings.Builder

	query.WriteString(
		"SELECT id, name, role FROM users WHERE name = '",
	)

	query.WriteString(name)

	query.WriteString("'")

	sqlQuery := query.String()

	logQuery(sqlQuery)

	rows, err := db.Query(sqlQuery)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	defer rows.Close()

	writeUsers(w, rows)
}

// ======================================================
// 04. fmt.Fprintf
// ======================================================

func vulnFprintf(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")

	var query strings.Builder

	fmt.Fprintf(
		&query,
		"SELECT id, name, role FROM users WHERE name = '%s'",
		name,
	)

	sqlQuery := query.String()

	logQuery(sqlQuery)

	rows, err := db.Query(sqlQuery)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	defer rows.Close()

	writeUsers(w, rows)
}

// ======================================================
// 05. IN (...) + strings.Join
// ======================================================

func vulnIN(w http.ResponseWriter, r *http.Request) {
	names := r.URL.Query()["name"]

	if len(names) == 0 {
		http.Error(w, "name required", 400)
		return
	}

	query := fmt.Sprintf(
		"SELECT id, name, role FROM users WHERE name IN ('%s')",
		strings.Join(names, "','"),
	)

	logQuery(query)

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	defer rows.Close()

	writeUsers(w, rows)
}

// ======================================================
// 06. LIKE
// ======================================================

func vulnLIKE(w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("search")

	query := fmt.Sprintf(
		"SELECT id, name, role FROM users WHERE name LIKE '%%%s%%'",
		search,
	)

	logQuery(query)

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	defer rows.Close()

	writeUsers(w, rows)
}

// ======================================================
// 07. UPDATE
// ======================================================

func vulnUPDATE(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	role := r.URL.Query().Get("role")

	query := fmt.Sprintf(
		"UPDATE users SET role='%s' WHERE id=%s",
		role,
		id,
	)

	logQuery(query)

	_, err := db.Exec(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	fmt.Fprintln(w, "updated")
}

// ======================================================
// 08. DELETE
// ======================================================

func vulnDELETE(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")

	query := fmt.Sprintf(
		"DELETE FROM users WHERE id=%s",
		id,
	)

	logQuery(query)

	_, err := db.Exec(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	fmt.Fprintln(w, "deleted")
}

// ======================================================
// 09. INSERT
// ======================================================

func vulnINSERT(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	role := r.URL.Query().Get("role")

	query := fmt.Sprintf(
		"INSERT INTO users(name, role) VALUES('%s', '%s')",
		name,
		role,
	)

	logQuery(query)

	_, err := db.Exec(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	fmt.Fprintln(w, "inserted")
}

// ======================================================
// 10. ORDER BY
// ======================================================

func vulnORDER(w http.ResponseWriter, r *http.Request) {
	sort := r.URL.Query().Get("sort")

	query := fmt.Sprintf(
		"SELECT id, name, role FROM users ORDER BY %s",
		sort,
	)

	logQuery(query)

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	defer rows.Close()

	writeUsers(w, rows)
}

// ======================================================
// 11. LIMIT
// ======================================================

func vulnLIMIT(w http.ResponseWriter, r *http.Request) {
	limit := r.URL.Query().Get("limit")

	query := fmt.Sprintf(
		"SELECT id, name, role FROM users LIMIT %s",
		limit,
	)

	logQuery(query)

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	defer rows.Close()

	writeUsers(w, rows)
}

// ======================================================
// 12. Dynamic WHERE
// ======================================================

func vulnWHERE(w http.ResponseWriter, r *http.Request) {
	field := r.URL.Query().Get("field")
	value := r.URL.Query().Get("value")

	query := fmt.Sprintf(
		"SELECT id, name, role FROM users WHERE %s = '%s'",
		field,
		value,
	)

	logQuery(query)

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	defer rows.Close()

	writeUsers(w, rows)
}

// ======================================================
// 13. Prepare too late
// ======================================================

func vulnFakePrepare(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")

	// Vulnerability already happened here.
	query := fmt.Sprintf(
		"SELECT id, name, role FROM users WHERE name='%s'",
		name,
	)

	logQuery(query)

	stmt, err := db.Prepare(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	defer stmt.Close()

	rows, err := stmt.Query()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	defer rows.Close()

	writeUsers(w, rows)
}

// ======================================================
// 14. Second-order SQLi
// ======================================================

// First request stores attacker-controlled data.

func storeSecondOrder(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")

	_, err := db.Exec(
		"INSERT INTO saved_filters(filter) VALUES(?)",
		filter,
	)

	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	fmt.Fprintln(w, "filter stored")
}

// Later the stored value becomes SQL code.

func useSecondOrder(w http.ResponseWriter, r *http.Request) {
	var filter string

	err := db.QueryRow(
		"SELECT filter FROM saved_filters ORDER BY id DESC LIMIT 1",
	).Scan(&filter)

	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	query := fmt.Sprintf(
		"SELECT id, name, role FROM users WHERE %s",
		filter,
	)

	logQuery(query)

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	defer rows.Close()

	writeUsers(w, rows)
}

// ======================================================
// SAFE SELECT
// ======================================================

func safeSelect(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")

	query := `
		SELECT id, name, role
		FROM users
		WHERE name = ?
	`

	logQuery(query)
	log.Println("PARAM:", name)

	rows, err := db.Query(query, name)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	defer rows.Close()

	writeUsers(w, rows)
}

// ======================================================
// SAFE UPDATE
// ======================================================

func safeUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	role := r.URL.Query().Get("role")

	query := `
		UPDATE users
		SET role = ?
		WHERE id = ?
	`

	logQuery(query)
	log.Println("PARAMS:", role, id)

	_, err := db.Exec(query, role, id)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	fmt.Fprintln(w, "updated")
}

// ======================================================
// SAFE ORDER BY
// ======================================================

func safeOrder(w http.ResponseWriter, r *http.Request) {
	sort := r.URL.Query().Get("sort")

	allowed := map[string]string{
		"name": "name",
		"id":   "id",
		"role": "role",
	}

	column, ok := allowed[sort]
	if !ok {
		http.Error(w, "invalid sort", 400)
		return
	}

	query := fmt.Sprintf(
		"SELECT id, name, role FROM users ORDER BY %s",
		column,
	)

	logQuery(query)

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	defer rows.Close()

	writeUsers(w, rows)
}

// ======================================================
// Helpers
// ======================================================

func logQuery(query string) {
	log.Println("----------------------------------------")
	log.Println("QUERY:", query)
	log.Println("----------------------------------------")
}

func writeUsers(w http.ResponseWriter, rows *sql.Rows) {
	for rows.Next() {
		var (
			id   int
			name string
			role string
		)

		err := rows.Scan(
			&id,
			&name,
			&role,
		)

		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		fmt.Fprintf(
			w,
			"id=%d name=%s role=%s\n",
			id,
			name,
			role,
		)
	}
}
