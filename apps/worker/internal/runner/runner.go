package runner

import (
	"context"
	"log"
	"time"

	"github.com/nebula-panel/nebula/apps/worker/internal/config"
	"github.com/nebula-panel/nebula/apps/worker/internal/jobs"
	"github.com/nebula-panel/nebula/apps/worker/internal/tasks"
)

type Runner struct {
	cfg config.Config
	tc  *tasks.Client
}

func New(cfg config.Config) *Runner {
	return &Runner{cfg: cfg, tc: tasks.New(cfg.AgentSocket, cfg.AgentSharedSecret)}
}

func (r *Runner) Run(ctx context.Context) error {
	sslTicker := time.NewTicker(r.cfg.SSLRenewInterval)
	backupTicker := time.NewTicker(r.cfg.BackupInterval)
	defer sslTicker.Stop()
	defer backupTicker.Stop()

	log.Printf("nebula-worker started ssl_interval=%s backup_interval=%s", r.cfg.SSLRenewInterval, r.cfg.BackupInterval)

	jobs.RunSSLRenew(ctx, r.tc, r.cfg.SSLRenewTargets)
	jobs.RunBackup(ctx, r.tc, r.cfg.BackupScope)

	for {
		select {
		case <-ctx.Done():
			log.Printf("nebula-worker stopped")
			return nil
		case <-sslTicker.C:
			jobs.RunSSLRenew(ctx, r.tc, r.cfg.SSLRenewTargets)
		case <-backupTicker.C:
			jobs.RunBackup(ctx, r.tc, r.cfg.BackupScope)
		}
	}
}
