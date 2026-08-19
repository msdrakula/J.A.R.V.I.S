package httpclient

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/msdrakula/J.A.R.V.I.S/internal/config"
)

func TestClientDo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	client, err := NewClient(config.HTTPConfig{
		TimeoutSeconds:   5,
		RetryCount:       1,
		RetryDelayMillis: 10,
		RateLimitPerSec:  0,
		UserAgents:       []string{"test-agent"},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	resp, err := client.Do(RequestOptions{Method: "GET", URL: server.URL, FollowRedirects: true})
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	if string(resp.Body) != "ok" {
		t.Fatalf("unexpected body: %s", string(resp.Body))
	}
	if resp.Duration <= 0 {
		t.Fatal("expected positive duration")
	}
}

func TestClientNilSafe(t *testing.T) {
	var client *Client
	if _, err := client.Do(RequestOptions{URL: "http://example.com"}); err == nil {
		t.Fatal("expected error for nil client")
	}
	empty := &Client{}
	if _, err := empty.Do(RequestOptions{URL: "http://example.com"}); err == nil {
		t.Fatal("expected error for uninitialized client")
	}
}

func TestNewClientZeroConfig(t *testing.T) {
	client, err := NewClient(config.HTTPConfig{})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if client == nil || client.httpClient == nil {
		t.Fatal("expected initialized client")
	}
}

func TestClientTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(config.HTTPConfig{
		TimeoutSeconds:   1,
		RetryCount:       0,
		RetryDelayMillis: 10,
		RateLimitPerSec:  0,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = client.Do(RequestOptions{Method: "GET", URL: server.URL, FollowRedirects: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
