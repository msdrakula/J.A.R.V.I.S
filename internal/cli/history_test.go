package cli

import (
	"strings"
	"testing"
	"time"
)

func TestParseSinceHours(t *testing.T) {
	before := time.Now()
	got, err := parseSince("24h")
	if err != nil {
		t.Fatalf("parseSince: %v", err)
	}
	expected := before.Add(-24 * time.Hour)
	if got.Sub(expected) > time.Minute || expected.Sub(got) > time.Minute {
		t.Fatalf("expected ~%v, got %v", expected, got)
	}
}

func TestParseSinceDays(t *testing.T) {
	before := time.Now()
	got, err := parseSince("7d")
	if err != nil {
		t.Fatalf("parseSince: %v", err)
	}
	expected := before.Add(-7 * 24 * time.Hour)
	if got.Sub(expected) > time.Minute || expected.Sub(got) > time.Minute {
		t.Fatalf("expected ~%v, got %v", expected, got)
	}
}

func TestParseSinceInvalid(t *testing.T) {
	if _, err := parseSince("nonsense"); err == nil {
		t.Fatal("expected error for invalid value")
	}
	if _, err := parseSince("xd"); err == nil {
		t.Fatal("expected error for invalid days value")
	}
}

func TestRenderPathTree(t *testing.T) {
	rows := []map[string]interface{}{
		{"url": "https://example.com/", "status_code": int64(200)},
		{"url": "https://example.com/admin", "status_code": int64(301)},
		{"url": "https://example.com/admin/login", "status_code": int64(200)},
		{"url": "https://example.com/admin/config", "status_code": int64(403)},
	}

	tree := renderPathTree(rows)

	for _, want := range []string{"/admin", "/login", "/config", "├─", "└─"} {
		if !strings.Contains(tree, want) {
			t.Fatalf("expected tree to contain %q, got:\n%s", want, tree)
		}
	}
}

func TestParseIntValue(t *testing.T) {
	if got := parseIntValue(int64(42)); got != 42 {
		t.Fatalf("int64: got %d", got)
	}
	if got := parseIntValue("80"); got != 80 {
		t.Fatalf("string: got %d", got)
	}
	if got := parseIntValue(nil); got != 0 {
		t.Fatalf("nil: got %d", got)
	}
}
