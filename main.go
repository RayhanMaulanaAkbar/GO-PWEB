package main

import (
	"html/template"
	"log"
	"net/http"
	"time"
)

var tpl = template.Must(
	template.New("").Funcs(template.FuncMap{
		"inc": func(i int) int { return i + 1 },
	}).ParseGlob("templates/*.html"))

func main() {
	connectDB()
	defer db.Close()

	go cleanupSessions()

	mux := http.NewServeMux()

	// Public pages
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("POST /logout", requireLogin(func(w http.ResponseWriter, r *http.Request, s Session) {
		logoutHandler(w, r)
	}))
	mux.HandleFunc("POST /api/login", apiLoginHandler)

	// Any logged-in user
	mux.HandleFunc("GET /{$}", requireLogin(indexHandler))
	mux.HandleFunc("/create", requireLogin(createHandler))
	mux.HandleFunc("/edit", requireLogin(editHandler))
	mux.HandleFunc("GET /api-demo", requireLogin(apiDemoHandler))

	// Admins only
	mux.HandleFunc("POST /delete", requireAdmin(deleteHandler))
	mux.HandleFunc("/users", requireAdmin(usersHandler))

	// JSON API
	mux.HandleFunc("GET /api/me", apiRequireLogin(apiMeHandler))
	mux.HandleFunc("POST /api/logout", apiRequireLogin(apiLogoutHandler))
	mux.HandleFunc("GET /api/majors", apiRequireLogin(apiListMajors))
	mux.HandleFunc("GET /api/students", apiRequireLogin(apiListStudents))
	mux.HandleFunc("GET /api/students/{id}", apiRequireLogin(apiGetStudent))
	mux.HandleFunc("POST /api/students", apiRequireLogin(apiCreateStudent))
	mux.HandleFunc("PUT /api/students/{id}", apiRequireLogin(apiUpdateStudent))
	mux.HandleFunc("DELETE /api/students/{id}", apiRequireAdmin(apiDeleteStudent))

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           securityHeaders(limitBody(mux)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Println("Server running at http://localhost:8080")
	log.Fatal(srv.ListenAndServe())
}
