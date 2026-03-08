package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps a SQLite connection for BigBanFan persistence.
type DB struct {
	conn *sql.DB
}

// Ban is one row from the bans table.
type Ban struct {
	ID        int64
	IP        string
	DedupeID  string
	BannedAt  time.Time
	ExpiresAt time.Time
	Source    string // originating node_id
}

// Open opens (or creates) the SQLite database at path, running schema migrations.
func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, fmt.Errorf("db: create dir: %w", err)
	}
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("db: open: %w", err)
	}
	d := &DB{conn: conn}
	if err := d.migrate(); err != nil {
		conn.Close()
		return nil, err
	}
	return d, nil
}

// Close shuts down the database connection.
func (d *DB) Close() error { return d.conn.Close() }

func (d *DB) migrate() error {
	_, err := d.conn.Exec(`CREATE TABLE IF NOT EXISTS bans (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		ip         TEXT    NOT NULL,
		dedupe_id  TEXT    NOT NULL UNIQUE,
		banned_at  INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		source     TEXT    NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_bans_expires ON bans(expires_at);
	CREATE INDEX IF NOT EXISTS idx_bans_ip ON bans(ip);`)
	if err != nil {
		return fmt.Errorf("db: migrate: %w", err)
	}
	return nil
}

// Insert persists a new ban entry.  Returns an error if the dedupe_id already exists.
func (d *DB) Insert(ip, dedupeID, source string, bannedAt, expiresAt time.Time) error {
	_, err := d.conn.Exec(
		`INSERT OR IGNORE INTO bans(ip, dedupe_id, banned_at, expires_at, source)
		 VALUES (?, ?, ?, ?, ?)`,
		ip, dedupeID, bannedAt.Unix(), expiresAt.Unix(), source,
	)
	return err
}

// ExistsDedupe returns true if the dedupe_id is already in the database.
func (d *DB) ExistsDedupe(dedupeID string) (bool, error) {
	var n int
	err := d.conn.QueryRow(`SELECT COUNT(1) FROM bans WHERE dedupe_id = ?`, dedupeID).Scan(&n)
	return n > 0, err
}

// IsActiveBan returns true if ip already has an unexpired ban in the database.
func (d *DB) IsActiveBan(ip string) (bool, error) {
	var n int
	err := d.conn.QueryRow(
		`SELECT COUNT(1) FROM bans WHERE ip = ? AND expires_at > ?`,
		ip, time.Now().Unix(),
	).Scan(&n)
	return n > 0, err
}

// GetActive returns all bans that have not yet expired (expires_at > now).
func (d *DB) GetActive() ([]Ban, error) {
	now := time.Now().Unix()
	rows, err := d.conn.Query(
		`SELECT id, ip, dedupe_id, banned_at, expires_at, source
		 FROM bans WHERE expires_at > ?`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanBans(rows)
}

// GetExpired returns bans whose expires_at <= now that have not been cleared.
func (d *DB) GetExpired() ([]Ban, error) {
	now := time.Now().Unix()
	rows, err := d.conn.Query(
		`SELECT id, ip, dedupe_id, banned_at, expires_at, source
		 FROM bans WHERE expires_at <= ?`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanBans(rows)
}

// DeleteByDedupeID removes a ban row by dedupe_id.
func (d *DB) DeleteByDedupeID(dedupeID string) error {
	_, err := d.conn.Exec(`DELETE FROM bans WHERE dedupe_id = ?`, dedupeID)
	return err
}

// RemoveBan deletes all ban rows for the given IP address (active and expired).
// Called when an UNBAN event is processed.
func (d *DB) RemoveBan(ip string) error {
	_, err := d.conn.Exec(`DELETE FROM bans WHERE ip = ?`, ip)
	return err
}

// SearchBans returns a paginated, filtered slice of bans for management clients.
//
// Parameters:
//   - search: if non-empty, filter rows where ip LIKE '%search%' (IPv4, IPv6, CIDR strings all match)
//   - filterSource: if non-empty, limit to bans with source = filterSource
//   - activeOnly: if true, only return bans with expires_at > now
//   - page: 1-indexed page number
//   - pageSize: records per page (caller should clamp to a reasonable max)
func (d *DB) SearchBans(search, filterSource string, activeOnly bool, page, pageSize int) ([]Ban, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 25
	}
	offset := (page - 1) * pageSize

	query, args := buildBanQuery(
		`SELECT id, ip, dedupe_id, banned_at, expires_at, source`,
		search, filterSource, activeOnly,
		fmt.Sprintf(" ORDER BY banned_at DESC LIMIT %d OFFSET %d", pageSize, offset),
	)
	rows, err := d.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanBans(rows)
}

// CountBans returns the total number of bans matching the given filters.
// Use this alongside SearchBans to build pagination controls in the GUI.
func (d *DB) CountBans(search, filterSource string, activeOnly bool) (int, error) {
	query, args := buildBanQuery(`SELECT COUNT(1)`, search, filterSource, activeOnly, "")
	var n int
	err := d.conn.QueryRow(query, args...).Scan(&n)
	return n, err
}

// buildBanQuery constructs the WHERE clause shared by SearchBans and CountBans.
func buildBanQuery(selectClause, search, filterSource string, activeOnly bool, suffix string) (string, []any) {
	q := selectClause + " FROM bans"
	var conditions []string
	var args []any

	if search != "" {
		conditions = append(conditions, "ip LIKE ?")
		args = append(args, "%"+search+"%")
	}
	if filterSource != "" {
		conditions = append(conditions, "source = ?")
		args = append(args, filterSource)
	}
	if activeOnly {
		conditions = append(conditions, "expires_at > ?")
		args = append(args, time.Now().Unix())
	}

	if len(conditions) > 0 {
		q += " WHERE " + joinConditions(conditions)
	}
	q += suffix
	return q, args
}

// joinConditions joins SQL condition strings with " AND ".
func joinConditions(conds []string) string {
	result := ""
	for i, c := range conds {
		if i > 0 {
			result += " AND "
		}
		result += c
	}
	return result
}

// AllDedupeIDs returns all dedupe IDs (active + expired) for seeding the in-memory set.
func (d *DB) AllDedupeIDs() ([]string, error) {
	rows, err := d.conn.Query(`SELECT dedupe_id FROM bans`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func scanBans(rows *sql.Rows) ([]Ban, error) {
	var bans []Ban
	for rows.Next() {
		var b Ban
		var bannedTS, expiresTS int64
		if err := rows.Scan(&b.ID, &b.IP, &b.DedupeID, &bannedTS, &expiresTS, &b.Source); err != nil {
			return nil, err
		}
		b.BannedAt = time.Unix(bannedTS, 0)
		b.ExpiresAt = time.Unix(expiresTS, 0)
		bans = append(bans, b)
	}
	return bans, rows.Err()
}
