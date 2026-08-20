package cli

import "testing"

func TestInterestingMark(t *testing.T) {
	if got := interestingMark(401, "http://x/backup/"); got != "← look" {
		t.Fatalf("backup: %q", got)
	}
	if got := interestingMark(200, "http://x/"); got != "ok" {
		t.Fatalf("ok: %q", got)
	}
	if got := interestingMark(401, "http://x/robots.txt"); got != "auth" {
		t.Fatalf("auth: %q", got)
	}
}

func TestUniqueStrings(t *testing.T) {
	got := uniqueStrings([]string{"a", "a", "b"})
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
}

func TestOutputDirOrDot(t *testing.T) {
	if got := outputDirOrDot("/home/kali/Documents/222/.jarvis.db"); got != "/home/kali/Documents/222" {
		t.Fatalf("got %s", got)
	}
}
