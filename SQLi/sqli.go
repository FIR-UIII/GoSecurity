package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strconv"
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

	http.HandleFunc("/concat/unsafe", concatUnsafe)
	http.HandleFunc("/concat/safe", concatSafe)

	http.HandleFunc("/sprintf/unsafe", sprintfUnsafe)
	http.HandleFunc("/sprintf/safe", sprintfSafe)

	http.HandleFunc("/builder/unsafe", builderUnsafe)
	http.HandleFunc("/builder/safe", builderSafe)

	http.HandleFunc("/fprintf/unsafe", fprintfUnsafe)
	http.HandleFunc("/fprintf/safe", fprintfSafe)

	http.HandleFunc("/in/unsafe", inUnsafe)
	http.HandleFunc("/in/safe", inSafe)

	http.HandleFunc("/like/unsafe", likeUnsafe)
	http.HandleFunc("/like/safe", likeSafe)

	// --------------------------------------------------
	// UPDATE / DELETE / INSERT
	// --------------------------------------------------

	http.HandleFunc("/update/unsafe", updateUnsafe)
	http.HandleFunc("/update/safe", updateSafe)

	http.HandleFunc("/delete/unsafe", deleteUnsafe)
	http.HandleFunc("/delete/safe", deleteSafe)

	http.HandleFunc("/insert/unsafe", insertUnsafe)
	http.HandleFunc("/insert/safe", insertSafe)

	// --------------------------------------------------
	// Dynamic SQL
	// --------------------------------------------------

	http.HandleFunc("/order/unsafe", orderUnsafe)
	http.HandleFunc("/order/safe", orderSafe)

	http.HandleFunc("/limit/unsafe", limitUnsafe)
	http.HandleFunc("/limit/safe", limitSafe)

	http.HandleFunc("/where/unsafe", whereUnsafe)
	http.HandleFunc("/where/safe", whereSafe)

	// --------------------------------------------------
	// Prepare incorrectly
	// --------------------------------------------------

	http.HandleFunc("/prepare/unsafe", prepareUnsafe)
	http.HandleFunc("/prepare/safe", prepareSafe)

	// --------------------------------------------------
	// $1, $2 placeholders
	// --------------------------------------------------

	http.HandleFunc("/placeholders/unsafe", placeholdersUnsafe)
	http.HandleFunc("/placeholders/safe", placeholdersSafe)

	// --------------------------------------------------
	// Dynamic table name with $1, $2
	// --------------------------------------------------

	http.HandleFunc("/table/unsafe", tableUnsafe)
	http.HandleFunc("/table/safe", tableSafe)

	// --------------------------------------------------
	// Second-order SQLi
	// --------------------------------------------------

	http.HandleFunc("/second-order/store", secondOrderStore)
	http.HandleFunc("/second-order/use", secondOrderUse)

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
}

// ======================================================
// String concatenation
// ======================================================

func concatUnsafe(w http.ResponseWriter, r *http.Request) {
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

func concatSafe(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")

	query := "SELECT id, name, role FROM users WHERE name = ?"

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
// fmt.Sprintf
// ======================================================

func sprintfUnsafe(w http.ResponseWriter, r *http.Request) {
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

func sprintfSafe(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")

	// Sprintf only builds the static placeholder text, never the value.
	query := fmt.Sprintf(
		"SELECT id, name, role FROM users WHERE name = %s",
		"?",
	)

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
// strings.Builder
// ======================================================

func builderUnsafe(w http.ResponseWriter, r *http.Request) {
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

func builderSafe(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")

	var query strings.Builder

	query.WriteString("SELECT id, name, role FROM users WHERE name = ?")

	sqlQuery := query.String()

	logQuery(sqlQuery)
	log.Println("PARAM:", name)

	rows, err := db.Query(sqlQuery, name)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	defer rows.Close()

	writeUsers(w, rows)
}

// ======================================================
// fmt.Fprintf
// ======================================================

func fprintfUnsafe(w http.ResponseWriter, r *http.Request) {
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

func fprintfSafe(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")

	var query strings.Builder

	// Fprintf only writes the static placeholder text, never the value.
	fmt.Fprintf(
		&query,
		"SELECT id, name, role FROM users WHERE name = %s",
		"?",
	)

	sqlQuery := query.String()

	logQuery(sqlQuery)
	log.Println("PARAM:", name)

	rows, err := db.Query(sqlQuery, name)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	defer rows.Close()

	writeUsers(w, rows)
}

// ======================================================
// IN (...) + strings.Join
// ======================================================

func inUnsafe(w http.ResponseWriter, r *http.Request) {
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

func inSafe(w http.ResponseWriter, r *http.Request) {
	names := r.URL.Query()["name"]

	if len(names) == 0 {
		http.Error(w, "name required", 400)
		return
	}

	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(names)), ",")

	query := fmt.Sprintf(
		"SELECT id, name, role FROM users WHERE name IN (%s)",
		placeholders,
	)

	args := make([]any, len(names))
	for i, n := range names {
		args[i] = n
	}

	logQuery(query)
	log.Println("PARAMS:", names)

	rows, err := db.Query(query, args...)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	defer rows.Close()

	writeUsers(w, rows)
}

// ======================================================
// LIKE
// ======================================================

func likeUnsafe(w http.ResponseWriter, r *http.Request) {
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

func likeSafe(w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("search")

	query := "SELECT id, name, role FROM users WHERE name LIKE ?"
	pattern := "%" + search + "%"

	logQuery(query)
	log.Println("PARAM:", pattern)

	rows, err := db.Query(query, pattern)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	defer rows.Close()

	writeUsers(w, rows)
}

// ======================================================
// UPDATE
// ======================================================

func updateUnsafe(w http.ResponseWriter, r *http.Request) {
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

func updateSafe(w http.ResponseWriter, r *http.Request) {
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
// DELETE
// ======================================================

func deleteUnsafe(w http.ResponseWriter, r *http.Request) {
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

func deleteSafe(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")

	query := "DELETE FROM users WHERE id = ?"

	logQuery(query)
	log.Println("PARAM:", id)

	_, err := db.Exec(query, id)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	fmt.Fprintln(w, "deleted")
}

// ======================================================
// INSERT
// ======================================================

func insertUnsafe(w http.ResponseWriter, r *http.Request) {
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

func insertSafe(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	role := r.URL.Query().Get("role")

	query := "INSERT INTO users(name, role) VALUES(?, ?)"

	logQuery(query)
	log.Println("PARAMS:", name, role)

	_, err := db.Exec(query, name, role)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	fmt.Fprintln(w, "inserted")
}

// ======================================================
// ORDER BY
// ======================================================

func orderUnsafe(w http.ResponseWriter, r *http.Request) {
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

func orderSafe(w http.ResponseWriter, r *http.Request) {
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
// LIMIT
// ======================================================

func limitUnsafe(w http.ResponseWriter, r *http.Request) {
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

func limitSafe(w http.ResponseWriter, r *http.Request) {
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || limit < 0 {
		http.Error(w, "invalid limit", 400)
		return
	}

	query := "SELECT id, name, role FROM users LIMIT ?"

	logQuery(query)
	log.Println("PARAM:", limit)

	rows, err := db.Query(query, limit)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	defer rows.Close()

	writeUsers(w, rows)
}

// ======================================================
// Dynamic WHERE
// ======================================================

func whereUnsafe(w http.ResponseWriter, r *http.Request) {
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

func whereSafe(w http.ResponseWriter, r *http.Request) {
	field := r.URL.Query().Get("field")
	value := r.URL.Query().Get("value")

	allowed := map[string]string{
		"name":  "name",
		"role":  "role",
		"email": "email",
		"id":    "id",
	}

	column, ok := allowed[field]
	if !ok {
		http.Error(w, "invalid field", 400)
		return
	}

	query := fmt.Sprintf(
		"SELECT id, name, role FROM users WHERE %s = ?",
		column,
	)

	logQuery(query)
	log.Println("PARAM:", value)

	rows, err := db.Query(query, value)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	defer rows.Close()

	writeUsers(w, rows)
}

// ======================================================
// Prepare too late
// ======================================================

func prepareUnsafe(w http.ResponseWriter, r *http.Request) {
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

func prepareSafe(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")

	query := "SELECT id, name, role FROM users WHERE name = ?"

	logQuery(query)
	log.Println("PARAM:", name)

	stmt, err := db.Prepare(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	defer stmt.Close()

	rows, err := stmt.Query(name)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	defer rows.Close()

	writeUsers(w, rows)
}

// ======================================================
// $x, $y placeholders
// ======================================================

func placeholdersUnsafe(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")

	query := "SELECT id, name, role FROM users WHERE name = $1"
	query = strings.Replace(query, "$1", "'"+name+"'", 1)

	logQuery(query)

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	defer rows.Close()

	writeUsers(w, rows)
}

func placeholdersSafe(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	role := r.URL.Query().Get("role")

	query := "SELECT id, name, role FROM users WHERE name = $1 AND role = $2"

	logQuery(query)
	log.Println("PARAMS:", name, role)

	rows, err := db.Query(query, name, role)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	defer rows.Close()

	writeUsers(w, rows)
}

// ======================================================
// Dynamic table name with $1, $2
// ======================================================

func tableUnsafe(w http.ResponseWriter, r *http.Request) {
	tableName := r.URL.Query().Get("table")
	name := r.URL.Query().Get("name")
	email := r.URL.Query().Get("email")

	query := fmt.Sprintf(`
		INSERT INTO %s (name, email)
		VALUES ($1, $2)
	`, tableName)

	logQuery(query)

	tx, err := db.Begin()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	if _, err = tx.Exec(query, name, email); err != nil {
		_ = tx.Rollback()
		http.Error(w, err.Error(), 500)
		return
	}

	if err = tx.Commit(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	fmt.Fprintln(w, "inserted")
}

func tableSafe(w http.ResponseWriter, r *http.Request) {
	tableName := r.URL.Query().Get("table")
	name := r.URL.Query().Get("name")
	email := r.URL.Query().Get("email")

	allowedTables := map[string]string{
		"users": "users",
	}

	validatedTableName, ok := allowedTables[tableName]
	if !ok {
		http.Error(w, "invalid table", 400)
		return
	}

	query := fmt.Sprintf(`
		INSERT INTO %s (name, email)
		VALUES ($1, $2)
	`, validatedTableName)

	logQuery(query)
	log.Println("PARAMS:", name, email)

	_, err := db.Exec(query, name, email)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	fmt.Fprintln(w, "inserted")
}

// ======================================================
// Second-order SQLi
// ======================================================

// First request stores attacker-controlled data safely, as a marker row
// in the users table (email column holds the stored filter).

func secondOrderStore(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")

	_, err := db.Exec(
		"INSERT INTO users(name, role, email) VALUES('_filter', 'meta', ?)",
		filter,
	)

	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	fmt.Fprintln(w, "filter stored")
}

// Later the stored value becomes SQL code.

func secondOrderUse(w http.ResponseWriter, r *http.Request) {
	var filter string

	err := db.QueryRow(
		"SELECT email FROM users WHERE name = '_filter' ORDER BY id DESC LIMIT 1",
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
