package main

import "time"

// User represents an authenticated account in the system.
type User struct {
	ID       int
	Username string
	Role     string // "user" or "admin"
}

// Session holds the active session for a logged-in user.
type Session struct {
	Token     string
	UserID    int
	CSRFToken string
	ExpiresAt time.Time
}

// MedicalRecord holds a patient's sensitive health data.
// last_updated_by and last_updated_at fulfil the auditability requirement.
type MedicalRecord struct {
	ID               int
	UserID           int
	Username         string // joined from users table
	FullName         string
	DateOfBirth      string
	BloodType        string
	Allergies        string
	Medications      string
	Phone            string // low-risk: user may self-update
	EmergencyContact string // low-risk: user may self-update
	GPName           string // admin-only
	Notes            string // admin-only
	LastUpdatedBy    string
	LastUpdatedAt    string
}
