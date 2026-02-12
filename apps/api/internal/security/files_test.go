package security

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSafeJoinRejectsEscape(t *testing.T) {
	root := t.TempDir()
	if _, err := SafeJoin(root, "../../etc/passwd"); err == nil {
		t.Fatalf("expected escape error")
	}
}

func TestCheckSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "inside")
	outside := t.TempDir()
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(inside, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := CheckSymlinkEscape(root, link); err == nil {
		t.Fatalf("expected symlink escape error")
	}
}
