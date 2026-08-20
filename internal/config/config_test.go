package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEmptyPathUsesDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load empty: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected defaults, got nil")
	}
	if cfg.OutputDir != "./results" {
		t.Fatalf("output dir: %s", cfg.OutputDir)
	}
	if cfg.HTTP.TimeoutSeconds <= 0 {
		t.Fatal("expected default timeout")
	}
	if len(cfg.HTTP.UserAgents) == 0 {
		t.Fatal("expected default user-agent")
	}
}

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("missing config must not fail: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected defaults, got nil")
	}
	if cfg.HTTP.TimeoutSeconds <= 0 || len(cfg.HTTP.UserAgents) == 0 {
		t.Fatalf("unsafe defaults: %+v", cfg.HTTP)
	}
}

func TestFindDataFileResolvesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := FindDataFile(path); got != path {
		t.Fatalf("FindDataFile: %q", got)
	}
	if got := FindDataFile(filepath.Join(dir, "missing.yaml")); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestNormalizeNilSafe(t *testing.T) {
	var cfg *Config
	cfg.Normalize()
	cfg.ApplyProfile(LevelProfile{TimeoutSeconds: 10, RateLimitPerSec: 5})
}

func TestHTTPNormalizeZeroValues(t *testing.T) {
	h := HTTPConfig{}
	h.Normalize()
	if h.TimeoutSeconds <= 0 || len(h.UserAgents) == 0 {
		t.Fatalf("got %+v", h)
	}
}
