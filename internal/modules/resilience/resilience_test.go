package resilience

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/msdrakula/J.A.R.V.I.S/internal/config"
	"github.com/msdrakula/J.A.R.V.I.S/internal/httpclient"
	"github.com/msdrakula/J.A.R.V.I.S/internal/storage"
)

func openTestStore(t *testing.T) *storage.Store {
	t.Helper()
	store, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestCheckDetectsReflection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body>You searched for: %s</body></html>", r.URL.Query().Get("q"))
	}))
	defer server.Close()

	store := openTestStore(t)
	scan := storage.Scan{ID: "scan-refl", Target: "test", StartedAt: "2026-08-19T10:00:00Z", Status: "running"}
	if err := store.CreateScan(scan); err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := store.AddParameter(scan.ID, storage.Parameter{
		URL: server.URL + "/search", Name: "q", ParamType: "query", Source: "form",
	}); err != nil {
		t.Fatalf("add parameter: %v", err)
	}

	client, err := httpclient.NewClient(config.HTTPConfig{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	checker := New(client, store)
	if err := checker.Check(scan.ID); err != nil {
		t.Fatalf("check: %v", err)
	}

	rows, err := store.Query(scan.ID, "SELECT severity, name FROM findings WHERE scan_id = ?", scan.ID)
	if err != nil {
		t.Fatalf("query findings: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("expected reflection finding, got none")
	}
	if !strings.Contains(fmt.Sprintf("%v", rows[0]["name"]), "reflected") {
		t.Fatalf("unexpected finding name: %v", rows[0]["name"])
	}
}

func TestCheckDetectsServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("q"), "'") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	store := openTestStore(t)
	scan := storage.Scan{ID: "scan-500", Target: "test", StartedAt: "2026-08-19T10:00:00Z", Status: "running"}
	if err := store.CreateScan(scan); err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := store.AddParameter(scan.ID, storage.Parameter{
		URL: server.URL + "/search", Name: "q", ParamType: "query", Source: "form",
	}); err != nil {
		t.Fatalf("add parameter: %v", err)
	}

	client, err := httpclient.NewClient(config.HTTPConfig{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	checker := New(client, store)
	if err := checker.Check(scan.ID); err != nil {
		t.Fatalf("check: %v", err)
	}

	rows, err := store.Query(scan.ID, "SELECT severity, name FROM findings WHERE scan_id = ?", scan.ID)
	if err != nil {
		t.Fatalf("query findings: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("expected error-handling finding, got none")
	}
	if fmt.Sprintf("%v", rows[0]["severity"]) != "medium" {
		t.Fatalf("expected medium severity, got %v", rows[0]["severity"])
	}
}

func TestCheckCleanApp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "static page, input discarded")
	}))
	defer server.Close()

	store := openTestStore(t)
	scan := storage.Scan{ID: "scan-clean", Target: "test", StartedAt: "2026-08-19T10:00:00Z", Status: "running"}
	if err := store.CreateScan(scan); err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := store.AddParameter(scan.ID, storage.Parameter{
		URL: server.URL + "/form", Name: "q", ParamType: "query", Source: "form",
	}); err != nil {
		t.Fatalf("add parameter: %v", err)
	}

	client, err := httpclient.NewClient(config.HTTPConfig{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	checker := New(client, store)
	if err := checker.Check(scan.ID); err != nil {
		t.Fatalf("check: %v", err)
	}

	rows, err := store.Query(scan.ID, "SELECT COUNT(*) AS cnt FROM findings WHERE scan_id = ?", scan.ID)
	if err != nil {
		t.Fatalf("query findings: %v", err)
	}
	if fmt.Sprintf("%v", rows[0]["cnt"]) != "0" {
		t.Fatalf("expected no findings for clean app, got %v", rows[0]["cnt"])
	}
}

func TestCheckNilGuards(t *testing.T) {
	checker := New(nil, nil)
	if err := checker.Check("any"); err == nil {
		t.Fatal("expected error for nil client/store")
	}
}

func TestBuildURL(t *testing.T) {
	got, err := buildURL("https://example.com/search?q=old&lang=en", "q", "MARK")
	if err != nil {
		t.Fatalf("buildURL: %v", err)
	}
	if !strings.Contains(got, "q=MARK") || !strings.Contains(got, "lang=en") {
		t.Fatalf("unexpected url: %s", got)
	}

	if _, err := buildURL("://bad-url", "q", "x"); err == nil {
		t.Fatal("expected error for malformed url")
	}
}
