package config

import "testing"

func TestSplitList(t *testing.T) {
	items := splitList("a, b ,,c")
	if len(items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(items))
	}
}
