package cli

import "testing"

func TestParseScanTargetURL(t *testing.T) {
	got, err := parseScanTarget("https://example.com/app")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Kind != targetWeb {
		t.Fatalf("kind: %v", got.Kind)
	}
	if got.Host != "example.com" {
		t.Fatalf("host: %s", got.Host)
	}
	if got.BaseURL != "https://example.com" {
		t.Fatalf("base: %s", got.BaseURL)
	}
}

func TestParseScanTargetDomain(t *testing.T) {
	got, err := parseScanTarget("example.com")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Kind != targetWeb || got.BaseURL != "https://example.com" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseScanTargetIP(t *testing.T) {
	got, err := parseScanTarget("192.168.1.10")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Kind != targetIP {
		t.Fatalf("kind: %v", got.Kind)
	}
	if got.Host != "192.168.1.10" {
		t.Fatalf("host: %s", got.Host)
	}
	if len(got.Ports) == 0 {
		t.Fatal("expected default ports")
	}
}

func TestParseScanTargetIPPort(t *testing.T) {
	got, err := parseScanTarget("10.0.0.5:8080")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Kind != targetIP || got.Host != "10.0.0.5" {
		t.Fatalf("got %+v", got)
	}
	if len(got.Ports) != 1 || got.Ports[0] != 8080 {
		t.Fatalf("ports: %v", got.Ports)
	}
}

func TestParseScanTargetHTTPIP(t *testing.T) {
	got, err := parseScanTarget("http://192.168.1.10")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Kind != targetWeb {
		t.Fatalf("http://IP must be treated as web target, got %v", got.Kind)
	}
	if got.BaseURL != "http://192.168.1.10" {
		t.Fatalf("base: %s", got.BaseURL)
	}
}

func TestParseScanTargetEmpty(t *testing.T) {
	if _, err := parseScanTarget("  "); err == nil {
		t.Fatal("expected error")
	}
}
