package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

type Scan struct {
	ID         string
	Target     string
	StartedAt  string
	FinishedAt string
	Modules    string
	Level      int
	Status     string
	OutputPath string
}

type DNSRecord struct {
	Domain     string
	RecordType string
	Value      string
	TTL        int
}

type TLSInfo struct {
	Domain     string
	Subject    string
	Issuer     string
	NotBefore  string
	NotAfter   string
}

type AssetPath struct {
	URL         string
	StatusCode  int
	Size        int
	ContentType string
}

type ServiceAvailability struct {
	Host    string
	Port    int
	State   string
	Service string
	Banner  string
}

type Finding struct {
	Host        string
	URL         string
	Severity    string
	Category    string
	Name        string
	Description string
	Evidence    string
}

type Parameter struct {
	URL       string
	Name      string
	ParamType string
	Source    string
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}

	return &Store{db: db}, nil
}

func migrate(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS scans (
			id TEXT PRIMARY KEY,
			target TEXT NOT NULL,
			started_at TEXT,
			finished_at TEXT,
			modules TEXT,
			level INTEGER,
			status TEXT,
			output_path TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS dns_records (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id TEXT,
			domain TEXT,
			record_type TEXT,
			value TEXT,
			ttl INTEGER
		);`,
		`CREATE TABLE IF NOT EXISTS tls_info (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id TEXT,
			domain TEXT,
			subject TEXT,
			issuer TEXT,
			not_before TEXT,
			not_after TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS asset_paths (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id TEXT,
			url TEXT,
			status_code INTEGER,
			size INTEGER,
			content_type TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS service_availability (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id TEXT,
			host TEXT,
			port INTEGER,
			state TEXT,
			service TEXT,
			banner TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS paths (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id TEXT,
			url TEXT,
			status_code INTEGER,
			size INTEGER,
			content_type TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS findings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id TEXT,
			host TEXT,
			url TEXT,
			severity TEXT,
			category TEXT,
			name TEXT,
			description TEXT,
			evidence TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS parameters (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id TEXT,
			url TEXT,
			param_name TEXT,
			param_type TEXT,
			source TEXT
		);`,
	}

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) CreateScan(scan Scan) error {
	_, err := s.db.Exec(`INSERT INTO scans (id, target, started_at, finished_at, modules, level, status, output_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		scan.ID, scan.Target, scan.StartedAt, scan.FinishedAt, scan.Modules, scan.Level, scan.Status, scan.OutputPath)
	return err
}

func (s *Store) UpdateScanStatus(id string, status string) error {
	_, err := s.db.Exec(`UPDATE scans SET status = ?, finished_at = ? WHERE id = ?`,
		status, time.Now().UTC().Format(time.RFC3339), id)
	return err
}

func (s *Store) GetCheckedURLs(scanID string) (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT DISTINCT url FROM paths WHERE scan_id = ?`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	checked := map[string]bool{}
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		checked[u] = true
	}
	return checked, rows.Err()
}

func (s *Store) AddDNSRecord(scanID string, record DNSRecord) error {
	_, err := s.db.Exec(`INSERT INTO dns_records (scan_id, domain, record_type, value, ttl) VALUES (?, ?, ?, ?, ?)`,
		scanID, record.Domain, record.RecordType, record.Value, record.TTL)
	return err
}

func (s *Store) AddTLSInfo(scanID string, info TLSInfo) error {
	_, err := s.db.Exec(`INSERT INTO tls_info (scan_id, domain, subject, issuer, not_before, not_after) VALUES (?, ?, ?, ?, ?, ?)`,
		scanID, info.Domain, info.Subject, info.Issuer, info.NotBefore, info.NotAfter)
	return err
}

func (s *Store) AddAssetPath(scanID string, path AssetPath) error {
	_, err := s.db.Exec(`INSERT INTO asset_paths (scan_id, url, status_code, size, content_type) VALUES (?, ?, ?, ?, ?)`,
		scanID, path.URL, path.StatusCode, path.Size, path.ContentType)
	return err
}

func (s *Store) AddServiceAvailability(scanID string, svc ServiceAvailability) error {
	_, err := s.db.Exec(`INSERT INTO service_availability (scan_id, host, port, state, service, banner) VALUES (?, ?, ?, ?, ?, ?)`,
		scanID, svc.Host, svc.Port, svc.State, svc.Service, svc.Banner)
	return err
}

func (s *Store) AddPath(scanID string, path AssetPath) error {
	_, err := s.db.Exec(`INSERT INTO paths (scan_id, url, status_code, size, content_type) VALUES (?, ?, ?, ?, ?)`,
		scanID, path.URL, path.StatusCode, path.Size, path.ContentType)
	return err
}

func (s *Store) AddFinding(scanID string, finding Finding) error {
	_, err := s.db.Exec(`INSERT INTO findings (scan_id, host, url, severity, category, name, description, evidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		scanID, finding.Host, finding.URL, finding.Severity, finding.Category, finding.Name, finding.Description, finding.Evidence)
	return err
}

func (s *Store) AddParameter(scanID string, param Parameter) error {
	_, err := s.db.Exec(`INSERT INTO parameters (scan_id, url, param_name, param_type, source) VALUES (?, ?, ?, ?, ?)`,
		scanID, param.URL, param.Name, param.ParamType, param.Source)
	return err
}

func (s *Store) GetParameters(scanID string) ([]Parameter, error) {
	rows, err := s.db.Query(`SELECT DISTINCT url, param_name, param_type, source FROM parameters WHERE scan_id = ?`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var params []Parameter
	for rows.Next() {
		var p Parameter
		if err := rows.Scan(&p.URL, &p.Name, &p.ParamType, &p.Source); err != nil {
			return nil, err
		}
		params = append(params, p)
	}
	return params, rows.Err()
}

func (s *Store) ListScans() ([]Scan, error) {
	rows, err := s.db.Query(`SELECT id, target, started_at, finished_at, modules, level, status, output_path FROM scans ORDER BY started_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []Scan
	for rows.Next() {
		var scan Scan
		if err := rows.Scan(&scan.ID, &scan.Target, &scan.StartedAt, &scan.FinishedAt, &scan.Modules, &scan.Level, &scan.Status, &scan.OutputPath); err != nil {
			return nil, err
		}
		scans = append(scans, scan)
	}
	return scans, rows.Err()
}

func (s *Store) Query(scanID string, query string, args ...interface{}) ([]map[string]interface{}, error) {
	if query == "" {
		return nil, fmt.Errorf("query is required")
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	results := []map[string]interface{}{}
	for rows.Next() {
		values := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := map[string]interface{}{}
		for i, col := range cols {
			row[col] = values[i]
		}
		results = append(results, row)
	}
	return results, rows.Err()
}
