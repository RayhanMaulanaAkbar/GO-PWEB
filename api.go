package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
)

// StudentJSON is the shape of a student in the API,
// for both responses and requests.
type StudentJSON struct {
	ID      int    `json:"id"`
	NIM     string `json:"nim"`
	Name    string `json:"name"`
	MajorID int    `json:"major_id"`
	Major   string `json:"major"`
}

type MajorJSON struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type MeJSON struct {
	ID        int    `json:"id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	CSRFToken string `json:"csrf_token"`
}

// ---------- JSON helpers ----------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// readJSON decodes the request body into dst.
func readJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		var tooBig *http.MaxBytesError

		if errors.As(err, &tooBig) {
			writeError(
				w,
				http.StatusRequestEntityTooLarge,
				"Request body is too large.",
			)
			return false
		}

		writeError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return false
	}

	return true
}

// pathID reads the {id} part of the URL.
func pathID(r *http.Request) (int, bool) {
	id, err := strconv.Atoi(r.PathValue("id"))
	return id, err == nil && id > 0
}

// ---------- Guards: like requireLogin, but they answer in JSON ----------

func apiRequireLogin(next protectedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, ok := currentSession(r)

		if !ok {
			writeError(w, http.StatusUnauthorized, "Login required.")
			return
		}

		if !csrfOK(r, s) {
			writeError(w, http.StatusForbidden, "Invalid or missing CSRF token.")
			return
		}

		next(w, r, s)
	}
}

func apiRequireAdmin(next protectedHandler) http.HandlerFunc {
	return apiRequireLogin(func(w http.ResponseWriter, r *http.Request, s Session) {
		if !s.IsAdmin() {
			writeError(w, http.StatusForbidden, "Admins only.")
			return
		}

		next(w, r, s)
	})
}

// ---------- Login ----------

func apiLoginHandler(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)

	if wait := loginLimiter.blocked(ip); wait > 0 {
		w.Header().Set(
			"Retry-After",
			strconv.Itoa(int(wait.Seconds())+1),
		)
		writeError(
			w,
			http.StatusTooManyRequests,
			"Too many failed attempts. Try again later.",
		)
		return
	}

	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if !readJSON(w, r, &in) {
		return
	}

	s, ok, err := authenticate(in.Username, in.Password)

	if err != nil {
		log.Println(err)
		writeError(w, http.StatusInternalServerError, "Server error.")
		return
	}

	if !ok {
		loginLimiter.fail(ip)
		writeError(
			w,
			http.StatusUnauthorized,
			"Incorrect username or password.",
		)
		return
	}

	loginLimiter.reset(ip)
	s = startSession(w, s)
	writeJSON(w, http.StatusOK, meOf(s))
}

func meOf(s Session) MeJSON {
	return MeJSON{
		ID:        s.UserID,
		Username:  s.Username,
		Role:      s.Role,
		CSRFToken: s.CSRF,
	}
}

func apiMeHandler(w http.ResponseWriter, r *http.Request, s Session) {
	writeJSON(w, http.StatusOK, meOf(s))
}

func apiLogoutHandler(w http.ResponseWriter, r *http.Request, s Session) {
	endSession(w, r)
	w.WriteHeader(http.StatusNoContent)
}

// ---------- Read ----------

const studentSelect = `
    SELECT s.id, s.nim, s.name, s.major_id, m.name
    FROM students s
    JOIN majors m ON s.major_id = m.id`

func apiListStudents(w http.ResponseWriter, r *http.Request, s Session) {
	rows, err := db.Query(studentSelect + " ORDER BY s.id")
	if err != nil {
		log.Println(err)
		writeError(w, http.StatusInternalServerError, "Server error.")
		return
	}
	defer rows.Close()

	list := []StudentJSON{}

	for rows.Next() {
		var st StudentJSON

		if err := rows.Scan(
			&st.ID, &st.NIM, &st.Name, &st.MajorID, &st.Major,
		); err != nil {
			log.Println(err)
			writeError(w, http.StatusInternalServerError, "Server error.")
			return
		}

		list = append(list, st)
	}

	if err := rows.Err(); err != nil {
		log.Println(err)
		writeError(w, http.StatusInternalServerError, "Server error.")
		return
	}

	writeJSON(w, http.StatusOK, list)
}

func getStudent(id int) (StudentJSON, error) {
	var st StudentJSON

	err := db.QueryRow(
		studentSelect+" WHERE s.id = ?", id,
	).Scan(
		&st.ID, &st.NIM, &st.Name, &st.MajorID, &st.Major,
	)

	return st, err
}

func apiGetStudent(w http.ResponseWriter, r *http.Request, s Session) {
	id, ok := pathID(r)

	if !ok {
		writeError(w, http.StatusBadRequest, "The id must be a positive number.")
		return
	}

	st, err := getStudent(id)

	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "Student not found.")
		return
	} else if err != nil {
		log.Println(err)
		writeError(w, http.StatusInternalServerError, "Server error.")
		return
	}

	writeJSON(w, http.StatusOK, st)
}

func apiListMajors(w http.ResponseWriter, r *http.Request, s Session) {
	majors, err := listMajors()

	if err != nil {
		log.Println(err)
		writeError(w, http.StatusInternalServerError, "Server error.")
		return
	}

	list := []MajorJSON{}

	for _, m := range majors {
		list = append(list, MajorJSON{
			ID:   m.ID,
			Name: m.Name,
		})
	}

	writeJSON(w, http.StatusOK, list)
}

// ---------- Write ----------

func validateInput(in StudentJSON) string {
	return validateStudent(StudentForm{
		NIM:     in.NIM,
		Name:    in.Name,
		MajorID: in.MajorID,
	})
}

func apiCreateStudent(w http.ResponseWriter, r *http.Request, s Session) {
	var in StudentJSON

	if !readJSON(w, r, &in) {
		return
	}

	if msg := validateInput(in); msg != "" {
		writeError(w, http.StatusUnprocessableEntity, msg)
		return
	}

	res, err := db.Exec(
		"INSERT INTO students (nim, name, major_id) VALUES (?, ?, ?)",
		in.NIM, in.Name, in.MajorID,
	)

	if err != nil {
		status := http.StatusInternalServerError

		if mysqlErrNo(err) == 1452 {
			status = http.StatusUnprocessableEntity
		}

		writeError(w, status, saveError(err))
		return
	}

	id, _ := res.LastInsertId()
	created, _ := getStudent(int(id))

	w.Header().Set("Location", "/api/students/"+strconv.Itoa(int(id)))
	writeJSON(w, http.StatusCreated, created)
}

func apiUpdateStudent(w http.ResponseWriter, r *http.Request, s Session) {
	id, ok := pathID(r)

	if !ok {
		writeError(w, http.StatusBadRequest, "The id must be a positive number.")
		return
	}

	if _, err := getStudent(id); errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "Student not found.")
		return
	} else if err != nil {
		log.Println(err)
		writeError(w, http.StatusInternalServerError, "Server error.")
		return
	}

	var in StudentJSON

	if !readJSON(w, r, &in) {
		return
	}

	if msg := validateInput(in); msg != "" {
		writeError(w, http.StatusUnprocessableEntity, msg)
		return
	}

	if _, err := db.Exec(
		"UPDATE students SET nim = ?, name = ?, major_id = ? WHERE id = ?",
		in.NIM, in.Name, in.MajorID, id,
	); err != nil {
		status := http.StatusInternalServerError

		if mysqlErrNo(err) == 1452 {
			status = http.StatusUnprocessableEntity
		}

		writeError(w, status, saveError(err))
		return
	}

	updated, _ := getStudent(id)
	writeJSON(w, http.StatusOK, updated)
}

func apiDeleteStudent(w http.ResponseWriter, r *http.Request, s Session) {
	id, ok := pathID(r)

	if !ok {
		writeError(w, http.StatusBadRequest, "The id must be a positive number.")
		return
	}

	res, err := db.Exec("DELETE FROM students WHERE id = ?", id)

	if err != nil {
		log.Println(err)
		writeError(w, http.StatusInternalServerError, "Server error.")
		return
	}

	if n, _ := res.RowsAffected(); n == 0 {
		writeError(w, http.StatusNotFound, "Student not found.")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ---------- The demo page ----------

type APIPage struct {
	User Session
}

func apiDemoHandler(w http.ResponseWriter, r *http.Request, s Session) {
	tpl.ExecuteTemplate(w, "api.html", APIPage{User: s})
}
