package recon

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/msdrakula/J.A.R.V.I.S/internal/config"
	"github.com/msdrakula/J.A.R.V.I.S/internal/httpclient"
)

func TestFetchRobots(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin\nAllow: /public\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client, err := httpclient.NewClient(config.HTTPConfig{
		TimeoutSeconds:   5,
		RetryCount:       0,
		RetryDelayMillis: 10,
		RateLimitPerSec:  0,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	auditor := New(client, nil)
	result, err := auditor.FetchRobots("scan-1", server.URL)
	if err != nil {
		t.Fatalf("fetch robots: %v", err)
	}

	joined := strings.Join(result.Rules, "\n")
	if !strings.Contains(joined, "Disallow: /admin") {
		t.Fatalf("expected disallow rule, got %v", result.Rules)
	}
}

func TestFetchSitemap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sitemap.xml" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/</loc></url>
  <url><loc>https://example.com/about</loc></url>
</urlset>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client, err := httpclient.NewClient(config.HTTPConfig{
		TimeoutSeconds:   5,
		RetryCount:       0,
		RetryDelayMillis: 10,
		RateLimitPerSec:  0,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	auditor := New(client, nil)
	result, err := auditor.FetchSitemap("scan-1", server.URL)
	if err != nil {
		t.Fatalf("fetch sitemap: %v", err)
	}
	if len(result.URLs) != 2 {
		t.Fatalf("expected 2 urls, got %d", len(result.URLs))
	}
}
