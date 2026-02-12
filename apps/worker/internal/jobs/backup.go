package jobs

import (
	"context"
	"log"

	"github.com/nebula-panel/nebula/apps/worker/internal/tasks"
)

func RunBackup(ctx context.Context, tc *tasks.Client, scope string) {
	if scope == "" {
		scope = "full"
	}
	err := tc.Submit(ctx, tasks.Request{Type: "backup_run", Target: "nightly", Args: map[string]string{"scope": scope}})
	if err != nil {
		log.Printf("backup-run: failed scope=%s err=%v", scope, err)
		return
	}
	log.Printf("backup-run: submitted scope=%s", scope)
}
