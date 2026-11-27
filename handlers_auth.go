package main

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strconv"

	"golang.org/x/crypto/bcrypt"
)

type LoginPage struct {
	Error string
}

// authenticate checks a username and password against the users table.
func authenticate(username, password string) (s Session, ok bool, err error) {
	var hash string

	err = db.QueryRow(
		"SELECT id, username, password, role FROM users WHERE username = ?",
		username,
	).Scan(&s.UserID, &s.Username, &hash, &s.Role)

	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, false, nil
	}

	if err != nil {
		return Session{}, false, err
	}

	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return Session{}, false, nil
	}

	return s, true, nil
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := currentSession(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	page := LoginPage{}

	if r.Method == http.MethodPost {
		ip := clientIP(r)

		if wait := loginLimiter.blocked(ip); wait > 0 {
			w.Header().Set(
				"Retry-After",
				strconv.Itoa(int(wait.Seconds())+1),
			)

			w.WriteHeader(http.StatusTooManyRequests)

			page.Error = "Too many failed attempts. Please wait a minute and try again."
			if err := tpl.ExecuteTemplate(w, "login.html", page); err != nil {
				log.Println(err)
				http.Error(w, "Server error", http.StatusInternalServerError)
				return
			}
			return
		}

		s, ok, err := authenticate(
			r.FormValue("username"),
			r.FormValue("password"),
		)

		if err != nil {
			log.Println(err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}

		if ok {
			loginLimiter.reset(ip)
			startSession(w, s)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		loginLimiter.fail(ip)

		// Deliberately vague: don't reveal which field was wrong.
		page.Error = "Incorrect username or password."
	}

	if err := tpl.ExecuteTemplate(w, "login.html", page); err != nil {
		log.Println(err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	endSession(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
