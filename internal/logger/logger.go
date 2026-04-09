package logger

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS log (
	id      INTEGER PRIMARY KEY AUTOINCREMENT,
	time    TEXT NOT NULL,
	kind    TEXT NOT NULL,
	domain  TEXT,
	dest    TEXT,
	extra   TEXT,
	session TEXT
);
CREATE INDEX IF NOT EXISTS idx_log_time    ON log(time);
CREATE INDEX IF NOT EXISTS idx_log_domain  ON log(domain);
CREATE INDEX IF NOT EXISTS idx_log_session ON log(session);
`

// Logger writes connection events to a SQLite database.
type Logger struct {
	db      *sql.DB
	session string
}

// Open opens or creates the log database at ~/.config/seki/seki.db.
// A new session ID is generated for grouping entries.
func Open() (*Logger, error) {
	dbPath, err := dbPath()
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	return &Logger{db: db, session: newSessionID()}, nil
}

// OpenReadOnly opens the log database for reading (no session ID needed).
func OpenReadOnly() (*Logger, error) {
	dbPath, err := dbPath()
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("no log database found at %s", dbPath)
	}

	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	return &Logger{db: db}, nil
}

// LogDNS records a DNS query.
func (l *Logger) LogDNS(domain, qtype string) {
	l.db.Exec(
		"INSERT INTO log (time, kind, domain, extra, session) VALUES (?, 'dns', ?, ?, ?)",
		now(), domain, qtype, l.session,
	)
}

// LogTCP records a TCP connection.
func (l *Logger) LogTCP(dest, sni string) {
	l.db.Exec(
		"INSERT INTO log (time, kind, dest, domain, session) VALUES (?, 'tcp', ?, ?, ?)",
		now(), dest, sni, l.session,
	)
}

// Entry represents a single log row.
type Entry struct {
	Time    string
	Kind    string
	Domain  string
	Dest    string
	Extra   string
	Session string
}

// Query returns log entries matching the given filters.
func (l *Logger) Query(domain string, limit int) ([]Entry, error) {
	var rows *sql.Rows
	var err error

	if domain != "" {
		rows, err = l.db.Query(
			"SELECT time, kind, domain, COALESCE(dest,''), COALESCE(extra,''), session FROM log WHERE domain LIKE ? ORDER BY time DESC LIMIT ?",
			"%"+domain+"%", limit,
		)
	} else {
		rows, err = l.db.Query(
			"SELECT time, kind, domain, COALESCE(dest,''), COALESCE(extra,''), session FROM log ORDER BY time DESC LIMIT ?",
			limit,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.Time, &e.Kind, &e.Domain, &e.Dest, &e.Extra, &e.Session); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}

	// Reverse to chronological order
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	return entries, nil
}

// QuerySince returns log entries since the given duration (for hook integration).
func (l *Logger) QuerySince(d time.Duration) ([]Entry, error) {
	since := time.Now().Add(-d).UTC().Format(time.RFC3339)
	rows, err := l.db.Query(
		"SELECT time, kind, domain, COALESCE(dest,''), COALESCE(extra,''), session FROM log WHERE time >= ? ORDER BY time",
		since,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.Time, &e.Kind, &e.Domain, &e.Dest, &e.Extra, &e.Session); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// Close closes the database.
func (l *Logger) Close() error {
	return l.db.Close()
}

// SessionID returns the current session identifier.
func (l *Logger) SessionID() string {
	return l.session
}

func dbPath() (string, error) {
	home, err := realUserHome()
	if err != nil {
		return "", fmt.Errorf("resolve home: %w", err)
	}
	dir := filepath.Join(home, ".config", "seki")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create config dir: %w", err)
	}
	// If running as root via sudo, fix ownership to the real user
	if sudoUID := os.Getenv("SUDO_UID"); sudoUID != "" {
		var uid, gid int
		fmt.Sscanf(sudoUID, "%d", &uid)
		fmt.Sscanf(os.Getenv("SUDO_GID"), "%d", &gid)
		os.Chown(dir, uid, gid)
	}
	dbFile := filepath.Join(dir, "seki.db")
	// Fix ownership of the DB file if it was just created by root
	if sudoUID := os.Getenv("SUDO_UID"); sudoUID != "" {
		var uid, gid int
		fmt.Sscanf(sudoUID, "%d", &uid)
		fmt.Sscanf(os.Getenv("SUDO_GID"), "%d", &gid)
		os.Chown(dbFile, uid, gid)
	}
	return dbFile, nil
}

// realUserHome returns the home directory of the real user (not root when using sudo).
func realUserHome() (string, error) {
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		// Running as root via sudo — use the original user's home
		home := os.Getenv("SUDO_HOME")
		if home != "" {
			return home, nil
		}
		// SUDO_HOME not always set; look up from passwd
		out, err := exec.Command("getent", "passwd", sudoUser).Output()
		if err == nil {
			fields := strings.SplitN(string(out), ":", 7)
			if len(fields) >= 6 {
				return fields[5], nil
			}
		}
	}
	return os.UserHomeDir()
}

func newSessionID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339)
}
