package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"net/http"
	"time"
)

// =============================================================================
// SESSION MANAGEMENT
// =============================================================================

// generateToken produces a cryptographically random 256-bit URL-safe token.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// createSession inserts a new session row and returns the Session struct.
// Each session carries its own per-session CSRF token.
func createSession(userID int) (*Session, error) {
	token, err := generateToken()
	if err != nil {
		return nil, err
	}
	csrfToken, err := generateToken()
	if err != nil {
		return nil, err
	}
	expires := time.Now().Add(2 * time.Hour)

	// Prepared statement – SQL injection protection.
	_, err = db.Exec(
		`INSERT INTO sessions (token, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)`,
		token, userID, csrfToken, expires)
	if err != nil {
		return nil, err
	}
	return &Session{Token: token, UserID: userID, CSRFToken: csrfToken, ExpiresAt: expires}, nil
}

// getSession reads the session cookie and returns the Session and User if valid.
// Returns nil, nil, nil when the user is not authenticated.
func getSession(r *http.Request) (*Session, *User, error) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil, nil, nil
	}

	var s Session
	var u User
	err = db.QueryRow(`
		SELECT s.token, s.user_id, s.csrf_token, s.expires_at,
		       u.id, u.username, u.role
		FROM   sessions s
		JOIN   users    u ON s.user_id = u.id
		WHERE  s.token = ? AND s.expires_at > CURRENT_TIMESTAMP`,
		cookie.Value).Scan(
		&s.Token, &s.UserID, &s.CSRFToken, &s.ExpiresAt,
		&u.ID, &u.Username, &u.Role)

	if err == sql.ErrNoRows {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	return &s, &u, nil
}

func deleteSession(token string) {
	db.Exec("DELETE FROM sessions WHERE token = ?", token)
}

// setSessionCookie writes the session cookie with HttpOnly and SameSite=Strict
// flags to prevent JavaScript access and CSRF from cross-site requests.
func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,                    // SECURITY: not accessible via JavaScript (XSS mitigation)
		SameSite: http.SameSiteStrictMode, // SECURITY: blocks cross-site request forgery
		MaxAge:   7200,                    // 2 hours
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1, // immediately expire
	})
}
