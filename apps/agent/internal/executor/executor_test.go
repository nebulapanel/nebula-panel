package executor

import (
	"context"
	"testing"

	"github.com/nebula-panel/nebula/apps/agent/internal/config"
)

func TestDenyUnknownTask(t *testing.T) {
	e := New(config.Config{DryRun: true})
	if err := e.Execute(context.Background(), Task{Type: "unknown"}); err == nil {
		t.Fatalf("expected unknown task error")
	}
}
