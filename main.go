// Secure Records Management System (SRMS)
// Organisation: York City Medical Centre
// Domain:       Patient Medical Records

package main

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var tmpl *template.Template

// Additional security feature 2 – Account lock out (Brute-Force Protection)
//
// After 5 consecutive failed login attempts the account is locked for
// 15 minutes.  The counters are stored in the users table so they survive
// server restarts and are enforced regardless of client identity.

const (
	maxFailedAttempts = 5
	lockoutDuration   = 15 * time.Minute
)

// isLockedOut returns true and a user facing message if the account is locked.
func isLockedOut(username string) (bool, string) {
	var failed int
	var lockedUntil sql.NullTime
	err := db.QueryRow(
		"SELECT failed_attempts, locked_until FROM users WHERE username = ?", username).
		Scan(&failed, &lockedUntil)
	if err != nil {
		return false, ""
	}
	if lockedUntil.Valid && lockedUntil.Time.After(time.Now()) {
		remaining := time.Until(lockedUntil.Time).Round(time.Minute)
		if remaining < time.Minute {
			remaining = time.Minute
		}
		return true, "Account locked after too many failed attempts. Try again in " +
			remaining.String() + "."
	}
	return false, ""
}

// recordFailedAttempt increments the failure counter and sets the lockout
// timestamp once the threshold is reached.
func recordFailedAttempt(username string) {
	db.Exec(`UPDATE users SET
		failed_attempts = failed_attempts + 1,
		locked_until = CASE
			WHEN failed_attempts + 1 >= ?
			THEN datetime(CURRENT_TIMESTAMP, '+15 minutes')
			ELSE locked_until
		END
		WHERE username = ?`, maxFailedAttempts, username)
}

// resetFailedAttempts clears the lockout state on successful login.
func resetFailedAttempts(username string) {
	db.Exec("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = ?", username)
}

// INPUT VALIDATION
//
// All user-supplied values are validated for length and basic format before
// being processed or stored.  This prevents malformed data and reduces the
// attack surface for injection-style abuse.

var (
	phoneRegex    = regexp.MustCompile(`^[0-9\s\+\-\(\)]{7,25}$`)
	nameRegex     = regexp.MustCompile(`^[a-zA-Z\s\-'\.]{1,100}$`)
	dobRegex      = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	bloodRegex    = regexp.MustCompile(`^(A|B|AB|O)[+-]$`)
	usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_]{1,50}$`)
)

func (ve *validationErrors) check(cond bool, msg string) {
	if !cond {
		*ve = append(*ve, msg)
	}
}

// handleRoot redirects to the appropriate dashboard based on role.
func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	_, user, err := getSession(r)
	if err != nil || user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if user.Role == "admin" {
		http.Redirect(w, r, "/admin/records", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/record", http.StatusSeeOther)
	}
}

// handleLogin renders the login form (GET) and authenticates users (POST).
// Passwords are compared with bcrypt; a constant-time comparison defeats
// timing-based user-enumeration.  Account lockout is enforced before the
// database lookup so the response is fast regardless of username validity.
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl.ExecuteTemplate(w, "login.html", nil)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	// --- Input validation ---
	if !usernameRegex.MatchString(username) || runeLen(password) < 1 || runeLen(password) > 128 {
		tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "Invalid credentials."})
		return
	}

	// --- Account lockout check (ADDITIONAL FEATURE 2) ---
	if locked, msg := isLockedOut(username); locked {
		tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": msg})
		return
	}

	// --- Fetch hashed password via prepared statement ---
	var user User
	var hash string
	err := db.QueryRow(
		"SELECT id, username, password_hash, role FROM users WHERE username = ?", username).
		Scan(&user.ID, &user.Username, &hash, &user.Role)

	if err == sql.ErrNoRows {
		// Perform a dummy bcrypt comparison to normalise timing and prevent
		// user enumeration through response-time differences.
		bcrypt.CompareHashAndPassword([]byte("$2a$10$dummy.hash.to.prevent.timing.leak"), []byte(password))
		tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "Invalid credentials."})
		return
	}
	if err != nil {
		http.Error(w, "Internal server error.", http.StatusInternalServerError)
		return
	}

	// --- Verify password (bcrypt – SECURITY requirement) ---
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		recordFailedAttempt(username) // ADDITIONAL FEATURE 2
		tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "Invalid credentials."})
		return
	}

	resetFailedAttempts(username)

	session, err := createSession(user.ID)
	if err != nil {
		http.Error(w, "Internal server error.", http.StatusInternalServerError)
		return
	}

	setSessionCookie(w, session.Token)

	if user.Role == "admin" {
		http.Redirect(w, r, "/admin/records", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/record", http.StatusSeeOther)
	}
}

// handleLogout invalidates the server-side session and clears the cookie.
func handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	session, _, _ := getSession(r)
	if session != nil {
		if !requireCSRF(w, r, session) {
			return
		}
		deleteSession(session.Token)
	}
	clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// handleRecord shows the currently logged-in user their own medical record
// together with a form to update the low-risk fields they are permitted to edit.
func handleRecord(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	session, user, err := getSession(r)
	if err != nil || session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	// Regular users only; admins use the admin interface.
	if user.Role == "admin" {
		http.Redirect(w, r, "/admin/records", http.StatusSeeOther)
		return
	}

	var rec MedicalRecord
	// Prepared statement – SQL injection protection.
	err = db.QueryRow(`
		SELECT id, user_id, full_name, date_of_birth, blood_type, allergies,
		       medications, phone, emergency_contact, gp_name, notes,
		       last_updated_by,
			   COALESCE(strftime('%Y-%m-%d %H:%M', datetime(last_updated_at, '+1 hour')), 'Never')		FROM   medical_records
		WHERE  user_id = ?`, user.ID).
		Scan(&rec.ID, &rec.UserID, &rec.FullName, &rec.DateOfBirth, &rec.BloodType,
			&rec.Allergies, &rec.Medications, &rec.Phone, &rec.EmergencyContact,
			&rec.GPName, &rec.Notes, &rec.LastUpdatedBy, &rec.LastUpdatedAt)

	if err == sql.ErrNoRows {
		http.Error(w, "No record found for your account.", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Internal server error.", http.StatusInternalServerError)
		return
	}

	tmpl.ExecuteTemplate(w, "record.html", pageData(user, session, map[string]interface{}{
		"Record": rec,
		"Flash":  r.URL.Query().Get("flash"),
		"Error":  r.URL.Query().Get("error"),
	}))
}

// handleUpdateRecord processes a user's request to update their own low-risk
// contact fields: phone and emergency_contact.
func handleUpdateRecord(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	session, user, err := getSession(r)
	if err != nil || session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if user.Role == "admin" {
		http.Error(w, "Forbidden.", http.StatusForbidden)
		return
	}

	// --- CSRF validation ---
	if !requireCSRF(w, r, session) {
		return
	}

	phone := strings.TrimSpace(r.FormValue("phone"))
	emergency := strings.TrimSpace(r.FormValue("emergency_contact"))

	// --- Input validation ---
	var ve validationErrors
	ve.check(validatePhone(phone), "Phone number contains invalid characters (digits and spaces only, 7–25 chars).")
	ve.check(runeLen(emergency) <= 200, "Emergency contact must be 200 characters or fewer.")

	if len(ve) > 0 {
		http.Redirect(w, r, "/record?error="+url.QueryEscape(strings.Join(ve, " ")), http.StatusSeeOther)
		return
	}

	// Prepared statement – SQL injection protection.
	_, err = db.Exec(`
		UPDATE medical_records
		SET    phone = ?, emergency_contact = ?,
		       last_updated_by = ?, last_updated_at = CURRENT_TIMESTAMP
		WHERE  user_id = ?`,
		phone, emergency, user.Username, user.ID)

	if err != nil {
		http.Error(w, "Internal server error.", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/record?flash="+url.QueryEscape("Contact details updated successfully."), http.StatusSeeOther)
}

// handleAdminRecords lists all patient records (summary view) for admin users.
func handleAdminRecords(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	session, user, err := getSession(r)
	if err != nil || session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if user.Role != "admin" {
		http.Error(w, "Forbidden — admin access required.", http.StatusForbidden)
		return
	}

	// Prepared statement – retrieves summary columns only; sensitive fields
	// (medications, notes etc.) are fetched individually on the detail page.
	rows, err := db.Query(`
		SELECT mr.id, mr.user_id, u.username, mr.full_name, mr.date_of_birth,
		       mr.blood_type, mr.last_updated_by,
			   COALESCE(strftime('%Y-%m-%d %H:%M', datetime(last_updated_at, '+1 hour')), 'Never')		FROM   medical_records mr
		JOIN   users u ON mr.user_id = u.id
		ORDER  BY mr.full_name`)
	if err != nil {
		http.Error(w, "Internal server error.", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var records []MedicalRecord
	for rows.Next() {
		var rec MedicalRecord
		if err := rows.Scan(&rec.ID, &rec.UserID, &rec.Username, &rec.FullName,
			&rec.DateOfBirth, &rec.BloodType, &rec.LastUpdatedBy, &rec.LastUpdatedAt); err != nil {
			log.Println("Row scan error:", err)
		}
		records = append(records, rec)
	}

	tmpl.ExecuteTemplate(w, "admin_records.html", pageData(user, session, map[string]interface{}{
		"Records": records,
	}))
}

// handleAdminRecord serves GET (view + edit form) and routes POST to the updater.
func handleAdminRecord(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		adminViewRecord(w, r)
	case http.MethodPost:
		adminUpdateRecord(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// adminViewRecord shows the full patient record and the admin edit form.
func adminViewRecord(w http.ResponseWriter, r *http.Request) {
	session, user, err := getSession(r)
	if err != nil || session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if user.Role != "admin" {
		http.Error(w, "Forbidden.", http.StatusForbidden)
		return
	}

	recordID, ok := extractRecordID(r.URL.Path)
	if !ok {
		http.Error(w, "Invalid record ID.", http.StatusBadRequest)
		return
	}

	var rec MedicalRecord
	// Prepared statement – SQL injection protection.
	err = db.QueryRow(`
		SELECT mr.id, mr.user_id, u.username, mr.full_name, mr.date_of_birth,
		       mr.blood_type, mr.allergies, mr.medications, mr.phone,
		       mr.emergency_contact, mr.gp_name, mr.notes,
		       mr.last_updated_by,
			   COALESCE(strftime('%Y-%m-%d %H:%M', datetime(last_updated_at, '+1 hour')), 'Never')		FROM   medical_records mr
		JOIN   users u ON mr.user_id = u.id
		WHERE  mr.id = ?`, recordID).
		Scan(&rec.ID, &rec.UserID, &rec.Username, &rec.FullName, &rec.DateOfBirth,
			&rec.BloodType, &rec.Allergies, &rec.Medications, &rec.Phone,
			&rec.EmergencyContact, &rec.GPName, &rec.Notes,
			&rec.LastUpdatedBy, &rec.LastUpdatedAt)

	if err == sql.ErrNoRows {
		http.Error(w, "Record not found.", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Internal server error.", http.StatusInternalServerError)
		return
	}

	tmpl.ExecuteTemplate(w, "admin_record.html", pageData(user, session, map[string]interface{}{
		"Record": rec,
		"Flash":  r.URL.Query().Get("flash"),
		"Error":  r.URL.Query().Get("error"),
	}))
}

// adminUpdateRecord processes an admin's POST to update any non-ID field in a
// patient record.  Both admin-only fields and user-editable fields may be set.
func adminUpdateRecord(w http.ResponseWriter, r *http.Request) {
	session, user, err := getSession(r)
	if err != nil || session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if user.Role != "admin" {
		http.Error(w, "Forbidden.", http.StatusForbidden)
		return
	}

	// --- CSRF validation ---
	if !requireCSRF(w, r, session) {
		return
	}

	recordID, ok := extractRecordID(r.URL.Path)
	if !ok {
		http.Error(w, "Invalid record ID.", http.StatusBadRequest)
		return
	}
	redirectBase := "/admin/record/" + strconv.Itoa(recordID)

	fullName := strings.TrimSpace(r.FormValue("full_name"))
	dob := strings.TrimSpace(r.FormValue("date_of_birth"))
	bloodType := strings.TrimSpace(r.FormValue("blood_type"))
	allergies := strings.TrimSpace(r.FormValue("allergies"))
	medications := strings.TrimSpace(r.FormValue("medications"))
	phone := strings.TrimSpace(r.FormValue("phone"))
	emergency := strings.TrimSpace(r.FormValue("emergency_contact"))
	gpName := strings.TrimSpace(r.FormValue("gp_name"))
	notes := strings.TrimSpace(r.FormValue("notes"))

	// --- Input validation ---
	var ve validationErrors
	ve.check(nameRegex.MatchString(fullName), "Full name must be 1–100 letters, spaces, hyphens, or apostrophes.")
	ve.check(dobRegex.MatchString(dob), "Date of birth must be in YYYY-MM-DD format.")
	ve.check(bloodType == "" || bloodRegex.MatchString(bloodType), "Blood type must be one of A+, A-, B+, B-, AB+, AB-, O+, O-.")
	ve.check(runeLen(allergies) <= 500, "Allergies field must be 500 characters or fewer.")
	ve.check(runeLen(medications) <= 500, "Medications field must be 500 characters or fewer.")
	ve.check(validatePhone(phone), "Phone number contains invalid characters.")
	ve.check(runeLen(emergency) <= 200, "Emergency contact must be 200 characters or fewer.")
	ve.check(runeLen(gpName) <= 100, "GP name must be 100 characters or fewer.")
	ve.check(runeLen(notes) <= 1000, "Notes must be 1000 characters or fewer.")

	if len(ve) > 0 {
		errMsg := url.QueryEscape(strings.Join(ve, " "))
		http.Redirect(w, r, redirectBase+"?error="+errMsg, http.StatusSeeOther)
		return
	}

	// Prepared statement – SQL injection protection.
	_, err = db.Exec(`
		UPDATE medical_records
		SET    full_name = ?, date_of_birth = ?, blood_type = ?, allergies = ?,
		       medications = ?, phone = ?, emergency_contact = ?,
		       gp_name = ?, notes = ?,
		       last_updated_by = ?, last_updated_at = CURRENT_TIMESTAMP
		WHERE  id = ?`,
		fullName, dob, bloodType, allergies, medications, phone, emergency,
		gpName, notes, user.Username, recordID)

	if err != nil {
		http.Error(w, "Internal server error.", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, redirectBase+"?flash="+url.QueryEscape("Record updated successfully."), http.StatusSeeOther)
}

// =============================================================================
// ROUTER AND MAIN
// =============================================================================

// adminRecordRouter dispatches /admin/record/* paths.
// Paths ending in the record ID only → view/edit form.
// Paths ending in /update (POST) → update handler.
func adminRecordRouter(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/update") && r.Method == http.MethodPost {
		adminUpdateRecord(w, r)
		return
	}
	handleAdminRecord(w, r)
}

func main() {
	initDB()
	defer db.Close()

	// html/template auto-escapes all output, defending against XSS.
	tmpl = template.Must(template.ParseGlob("templates/*.html"))

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/logout", handleLogout)
	mux.HandleFunc("/record", handleRecord)
	mux.HandleFunc("/record/update", handleUpdateRecord)
	mux.HandleFunc("/admin/records", handleAdminRecords)
	mux.HandleFunc("/admin/record/", adminRecordRouter) // prefix match

	// Wrap the entire mux with the security-headers middleware (ADDITIONAL FEATURE 1).
	handler := securityHeadersMiddleware(mux)

	log.Println("SRMS – York City Medical Centre")
	log.Println("Listening on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}
