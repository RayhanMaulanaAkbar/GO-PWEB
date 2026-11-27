package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"os"
	"sync"
	"time"
)

// Session is what we remember about a logged-in user.
type Session struct {
	UserID   int
	Username string
	Role     string
	CSRF     string
	Expires  time.Time
}

// A session that is not used for this long is forgotten.
var sessionTTL = 30 * time.Minute

// Set SECURE_COOKIES=1 when the site runs behind HTTPS.
var secureCookies = os.Getenv("SECURE_COOKIES") == "1"

func (s Session) IsAdmin() bool {
	return s.Role == "admin"
}

const cookieName = "session_id"

var (
	sessions   = map[string]Session{}
	sessionsMu sync.RWMutex
)

func newToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// startSession creates a new session token.
func startSession(w http.ResponseWriter, s Session) Session {
	token := newToken()
	s.CSRF = newToken()
	s.Expires = time.Now().Add(sessionTTL)

	sessionsMu.Lock()
	sessions[token] = s
	sessionsMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secureCookies,
		SameSite: http.SameSiteLaxMode,
	})

	return s
}

// currentSession retrieves and refreshes an active session.
func currentSession(r *http.Request) (Session, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return Session{}, false
	}

	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	s, ok := sessions[c.Value]
	if !ok {
		return Session{}, false
	}

	if time.Now().After(s.Expires) {
		delete(sessions, c.Value)
		return Session{}, false
	}

	// Activity keeps the session alive.
	s.Expires = time.Now().Add(sessionTTL)
	sessions[c.Value] = s

	return s, true
}

// cleanupSessions removes expired sessions.
func cleanupSessions() {
	for range time.Tick(time.Minute) {
		now := time.Now()

		sessionsMu.Lock()

		for token, s := range sessions {
			if now.After(s.Expires) {
				delete(sessions, token)
			}
		}

		sessionsMu.Unlock()
	}
}

// csrfOK checks the CSRF token for state-changing requests.
func csrfOK(r *http.Request, s Session) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}

	token := r.Header.Get("X-CSRF-Token")

	if token == "" {
		token = r.PostFormValue("csrf")
	}

	return subtle.ConstantTimeCompare(
		[]byte(token),
		[]byte(s.CSRF),
	) == 1
}

func endSession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		sessionsMu.Lock()
		delete(sessions, c.Value)
		sessionsMu.Unlock()
	}

	// Ask the browser to delete the cookie as well.
	http.SetCookie(w, &http.Cookie{
		Name:   cookieName,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}

// ---------- Middleware (the auth guard) ----------

type protectedHandler func(
	w http.ResponseWriter,
	r *http.Request,
	s Session,
)

// requireLogin: not logged in -> redirect to /login.
// A POST without the right CSRF token is refused.
func requireLogin(next protectedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, ok := currentSession(r)

		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if !csrfOK(r, s) {
			http.Error(
				w,
				"403 - Invalid or missing CSRF token.",
				http.StatusForbidden,
			)
			return
		}

		next(w, r, s)
	}
}

// requireAdmin: logged in AND role = admin, otherwise 403.
func requireAdmin(next protectedHandler) http.HandlerFunc {
	return requireLogin(func(w http.ResponseWriter, r *http.Request, s Session) {
		if !s.IsAdmin() {
			http.Error(
				w,
				"403 - Access denied. This page is for admins only.",
				http.StatusForbidden,
			)
			return
		}

		next(w, r, s)
	})
}
