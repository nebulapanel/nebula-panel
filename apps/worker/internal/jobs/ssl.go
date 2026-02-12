package jobs

import (
	"context"
	"log"

	"github.com/nebula-panel/nebula/apps/worker/internal/tasks"
)

func RunSSLRenew(ctx context.Context, tc *tasks.Client, targets []string) {
	if len(targets) == 0 {
		log.Printf("ssl-renew: no targets configured; skipping")
		return
	}
	for _, siteID := range targets {
		err := tc.Submit(ctx, tasks.Request{Type: "ssl_renew", Target: siteID})
		if err != nil {
			log.Printf("ssl-renew: failed for site=%s err=%v", siteID, err)
			continue
		}
		log.Printf("ssl-renew: submitted for site=%s", siteID)
	}
}
