package config

import "testing"

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
