package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/msdrakula/J.A.R.V.I.S/internal/storage"
)

func TestExportToNmapXML(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer store.Close()

	scan := storage.Scan{
		ID:         "scan-test-1",
		Target:     "example.com",
		StartedAt:  "2026-08-19T10:00:00Z",
		FinishedAt: "2026-08-19T10:05:00Z",
		Modules:    "availability",
		Level:      3,
		Status:     "completed",
		OutputPath: "./results",
	}
	if err := store.CreateScan(scan); err != nil {
		t.Fatalf("create scan: %v", err)
	}

	if err := store.AddServiceAvailability(scan.ID, storage.ServiceAvailability{
		Host: "example.com", Port: 443, State: "open", Service: "https",
	}); err != nil {
		t.Fatalf("add service: %v", err)
	}
	if err := store.AddFinding(scan.ID, storage.Finding{
		Host: "example.com", URL: "https://example.com/", Severity: "low",
		Category: "security-header", Name: "Missing security header",
		Description: "Missing security header: X-Frame-Options",
	}); err != nil {
		t.Fatalf("add finding: %v", err)
	}

	outPath := filepath.Join(t.TempDir(), "nmap.xml")
	if err := ExportToNmapXML(store, scan.ID, outPath); err != nil {
		t.Fatalf("export: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	content := string(data)

	for _, want := range []string{
		`<nmaprun scanner="jarvis"`,
		`<address addr="example.com" addrtype="hostname"`,
		`portid="443"`,
		`<state state="open"`,
		`<service name="https"`,
		`jarvis-finding`,
		`Missing security header`,
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, content)
		}
	}
}

func TestExportToNmapXMLScanNotFound(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer store.Close()

	outPath := filepath.Join(t.TempDir(), "nmap.xml")
	if err := ExportToNmapXML(store, "missing-id", outPath); err == nil {
		t.Fatal("expected error for missing scan")
	}
}

func TestExportToNmapXMLEmptyScan(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer store.Close()

	scan := storage.Scan{
		ID: "scan-empty", Target: "empty.local",
		StartedAt: "2026-08-19T10:00:00Z", FinishedAt: "2026-08-19T10:01:00Z",
		Status: "completed",
	}
	if err := store.CreateScan(scan); err != nil {
		t.Fatalf("create scan: %v", err)
	}

	outPath := filepath.Join(t.TempDir(), "nmap.xml")
	if err := ExportToNmapXML(store, scan.ID, outPath); err != nil {
		t.Fatalf("export: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !strings.Contains(string(data), `<nmaprun scanner="jarvis"`) {
		t.Fatalf("expected valid nmaprun document, got:\n%s", string(data))
	}
}
