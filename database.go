package main

import (
	"database/sql"
	"log"

	"golang.org/x/crypto/bcrypt"
)

// =============================================================================
// DATABASE INITIALISATION
// =============================================================================

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "srms.db")
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}
	// Enable WAL mode and foreign key enforcement for reliability and integrity.
	db.Exec("PRAGMA journal_mode=WAL")
	db.Exec("PRAGMA foreign_keys=ON")

	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		username        TEXT    UNIQUE NOT NULL,
		password_hash   TEXT    NOT NULL,
		role            TEXT    NOT NULL DEFAULT 'user',
		failed_attempts INTEGER NOT NULL DEFAULT 0,
		locked_until    DATETIME,
		created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS sessions (
		token      TEXT PRIMARY KEY,
		user_id    INTEGER NOT NULL,
		csrf_token TEXT    NOT NULL,
		expires_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	-- Sensitive records table.  All fields use prepared statements for access.
	-- last_updated_by / last_updated_at are set on every write (audit trail).
	CREATE TABLE IF NOT EXISTS medical_records (
		id                INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id           INTEGER NOT NULL UNIQUE,
		full_name         TEXT    NOT NULL,
		date_of_birth     TEXT    NOT NULL,
		blood_type        TEXT    NOT NULL DEFAULT '',
		allergies         TEXT    NOT NULL DEFAULT '',
		medications       TEXT    NOT NULL DEFAULT '',
		phone             TEXT    NOT NULL DEFAULT '',
		emergency_contact TEXT    NOT NULL DEFAULT '',
		gp_name           TEXT    NOT NULL DEFAULT '',
		notes             TEXT    NOT NULL DEFAULT '',
		last_updated_by   TEXT    NOT NULL DEFAULT 'system',
		last_updated_at   DATETIME,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);`

	if _, err := db.Exec(schema); err != nil {
		log.Fatal("Schema creation failed:", err)
	}

	seedData()
}

// seedData populates the database with one admin and three sample patients if
// the database is empty.  Passwords are bcrypt-hashed before storage.
func seedData() {
	var count int
	db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if count > 0 {
		return // already seeded
	}

	mkHash := func(pw string) string {
		h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		if err != nil {
			log.Fatal(err)
		}
		return string(h)
	}

	// Admin account
	db.Exec(`INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')`,
		"admin", mkHash("Admin@1234"))
	db.Exec(`INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')`,
		"admin2", mkHash("Admin@5678"))

	// Patient accounts and their records
	patients := []struct {
		username, password, name, dob, blood, allerg, meds, phone, ec, gp, notes string
	}{
		{
			"jsmith", "Pass@1234", "John Smith", "1985-03-15",
			"A+", "Penicillin", "Lisinopril 10mg daily",
			"07700 900001", "Jane Smith – 07700 900002",
			"Dr. H. Wilson", "Hypertension well-controlled. Annual review: March.",
		},
		{
			"emilyr", "Pass@1234", "Emily Roberts", "1992-07-22",
			"O-", "None known", "None",
			"07700 900003", "Tom Roberts – 07700 900004",
			"Dr. A. Patel", "Routine annual check-up due June.",
		},
		{
			"mbrown", "Pass@1234", "Michael Brown", "1978-11-08",
			"B+", "Aspirin, Ibuprofen", "Metformin 500mg twice daily",
			"07700 900005", "Susan Brown – 07700 900006",
			"Dr. S. Chen", "Type 2 diabetes – well managed. HbA1c stable.",
		},
		{
			"lthompson", "Pass@1234", "Laura Thompson", "1990-06-30",
			"AB+", "None known", "Sertraline 50mg daily",
			"07700 900007", "Mark Thompson – 07700 900008",
			"Dr. H. Wilson", "Mild anxiety and depression. Stable on current medication.",
		},
		{
			"rkaur", "Pass@1234", "Rajvir Kaur", "1975-02-14",
			"B-", "Latex", "Atorvastatin 20mg daily",
			"07700 900009", "Priya Kaur – 07700 900010",
			"Dr. A. Patel", "High cholesterol. Dietary advice given. Review in 6 months.",
		},
		{
			"dowens", "Pass@1234", "Daniel Owens", "2001-09-03",
			"O+", "None known", "Salbutamol inhaler as needed",
			"07700 900011", "Carol Owens – 07700 900012",
			"Dr. S. Chen", "Mild asthma. Well controlled. No recent flare-ups.",
		},
		{
			"fnguyen", "Pass@1234", "Fiona Nguyen", "1968-11-21",
			"A-", "Codeine", "Amlodipine 5mg daily, Ramipril 5mg daily",
			"07700 900013", "David Nguyen – 07700 900014",
			"Dr. H. Wilson", "Stage 2 hypertension. BP monitoring ongoing. Next review: July.",
		},
		{
			"gpatterson", "Pass@1234", "George Patterson", "1955-04-17",
			"O+", "Sulfonamides", "Warfarin 3mg daily, Bisoprolol 2.5mg daily",
			"07700 900015", "Helen Patterson – 07700 900016",
			"Dr. A. Patel", "Atrial fibrillation. INR stable. Monthly blood tests required.",
		},
		{
			"amelody", "Pass@1234", "Amara Melody", "1998-07-09",
			"AB-", "None known", "None",
			"07700 900017", "James Melody – 07700 900018",
			"Dr. S. Chen", "Healthy. Presented with fatigue – bloods normal. Follow up if symptoms persist.",
		},
		{
			"tbarrett", "Pass@1234", "Thomas Barrett", "1982-12-25",
			"A+", "Penicillin, NSAIDs", "Omeprazole 20mg daily, Co-codamol as needed",
			"07700 900019", "Sarah Barrett – 07700 900020",
			"Dr. H. Wilson", "Chronic lower back pain. Physiotherapy referral made.",
		},
		{
			"ychen", "Pass@1234", "Yuna Chen", "1995-03-08",
			"B+", "None known", "Levothyroxine 75mcg daily",
			"07700 900021", "Wei Chen – 07700 900022",
			"Dr. A. Patel", "Hypothyroidism. TSH levels stable. Annual thyroid panel due October.",
		},
		{
			"pmurphy", "Pass@1234", "Patrick Murphy", "1963-08-19",
			"O-", "Aspirin", "Metformin 1g twice daily, Gliclazide 80mg daily",
			"07700 900023", "Brigid Murphy – 07700 900024",
			"Dr. S. Chen", "Type 2 diabetes. HbA1c slightly elevated. Dietary review scheduled.",
		},
		{
			"swalker", "Pass@1234", "Sophie Walker", "1987-01-11",
			"A-", "None known", "Cetirizine 10mg daily",
			"07700 900025", "Ben Walker – 07700 900026",
			"Dr. H. Wilson", "Seasonal allergic rhinitis. Symptoms manageable with antihistamines.",
		},
	}

	for _, p := range patients {
		// Prepared statement used for INSERT (SQL-injection protection).
		res, err := db.Exec(
			`INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')`,
			p.username, mkHash(p.password))
		if err != nil {
			log.Println("Seed user error:", err)
			continue
		}
		uid, _ := res.LastInsertId()
		db.Exec(`INSERT INTO medical_records
			(user_id, full_name, date_of_birth, blood_type, allergies, medications,
			 phone, emergency_contact, gp_name, notes, last_updated_by, last_updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'system', CURRENT_TIMESTAMP)`,
			uid, p.name, p.dob, p.blood, p.allerg, p.meds,
			p.phone, p.ec, p.gp, p.notes)
	}
	log.Println("Database seeded.  Admin: admin/Admin@1234, admin2/Admin@5678  |  Patients: jsmith, emilyr, mbrown / Pass@1234")
}
