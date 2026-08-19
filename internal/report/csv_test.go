package report

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"testing"

	"github.com/msdrakula/J.A.R.V.I.S/internal/storage"
)

func TestExportFindingsCSV(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer store.Close()

	scan := storage.Scan{
		ID: "scan-csv-1", Target: "example.com",
		StartedAt: "2026-08-19T10:00:00Z", FinishedAt: "2026-08-19T10:05:00Z",
		Status: "completed",
	}
	if err := store.CreateScan(scan); err != nil {
		t.Fatalf("create scan: %v", err)
	}

	if err := store.AddFinding(scan.ID, storage.Finding{
		Host: "example.com", URL: "https://example.com/login", Severity: "medium",
		Category: "input-resilience", Name: "Improper error handling on unexpected input",
		Description: "Parameter \"q\" caused a 500 response",
	}); err != nil {
		t.Fatalf("add finding: %v", err)
	}

	outPath := filepath.Join(t.TempDir(), "report.csv")
	if err := ExportFindingsCSV(store, scan.ID, outPath); err != nil {
		t.Fatalf("export: %v", err)
	}

	file, err := os.Open(outPath)
	if err != nil {
		t.Fatalf("open output: %v", err)
	}
	defer file.Close()

	records, err := csv.NewReader(file).ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected header + 1 record, got %d rows", len(records))
	}

	header := records[0]
	if header[0] != "scan_id" || header[6] != "description" {
		t.Fatalf("unexpected header: %v", header)
	}

	row := records[1]
	if row[0] != scan.ID {
		t.Fatalf("expected scan_id %q, got %q", scan.ID, row[0])
	}
	if row[2] != "medium" || row[3] != "input-resilience" {
		t.Fatalf("unexpected severity/category: %v", row)
	}
	if row[5] != "https://example.com/login" {
		t.Fatalf("unexpected url: %q", row[5])
	}
}

func TestExportFindingsCSVEmpty(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer store.Close()

	scan := storage.Scan{
		ID: "scan-csv-empty", Target: "empty.local",
		StartedAt: "2026-08-19T10:00:00Z", FinishedAt: "2026-08-19T10:01:00Z",
		Status: "completed",
	}
	if err := store.CreateScan(scan); err != nil {
		t.Fatalf("create scan: %v", err)
	}

	outPath := filepath.Join(t.TempDir(), "report.csv")
	if err := ExportFindingsCSV(store, scan.ID, outPath); err != nil {
		t.Fatalf("export: %v", err)
	}

	file, err := os.Open(outPath)
	if err != nil {
		t.Fatalf("open output: %v", err)
	}
	defer file.Close()

	records, err := csv.NewReader(file).ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected only header row, got %d rows", len(records))
	}
}
