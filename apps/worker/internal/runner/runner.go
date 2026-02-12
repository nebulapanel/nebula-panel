package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-panel/nebula/apps/worker/internal/config"
	"github.com/nebula-panel/nebula/apps/worker/internal/jobs"
	"github.com/nebula-panel/nebula/apps/worker/internal/store"
	"github.com/nebula-panel/nebula/apps/worker/internal/tasks"
)

type Runner struct {
	cfg config.Config
	tc  *tasks.Client
	st  *store.Store
	id  string
}

func New(cfg config.Config) *Runner {
	host, _ := os.Hostname()
	id := host
	if id == "" {
		id = "worker"
	}
	id = id + ":" + strconv.Itoa(os.Getpid())
	return &Runner{cfg: cfg, tc: tasks.New(cfg.AgentSocket, cfg.AgentSharedSecret), id: id}
}

func (r *Runner) Run(ctx context.Context) error {
	dbCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	st, err := store.New(dbCtx, r.cfg.DatabaseURL, r.cfg.AppKey)
	if err != nil {
		return err
	}
	r.st = st
	defer r.st.Close()

	go r.runQueue(ctx)

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

func (r *Runner) runQueue(ctx context.Context) {
	pollDelay := 750 * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		j, ok, err := r.st.ClaimNextJob(ctx, r.id)
		if err != nil {
			log.Printf("job claim failed: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		if !ok {
			time.Sleep(pollDelay)
			continue
		}

		if err := r.executeJob(ctx, j); err != nil {
			log.Printf("job failed id=%s type=%s err=%v", j.ID, j.Type, err)
			_ = r.st.MarkJobFailed(ctx, j.ID, err.Error())
			continue
		}
		_ = r.st.MarkJobDone(ctx, j.ID, "ok")
	}
}

func (r *Runner) executeJob(ctx context.Context, j store.Job) error {
	switch j.Type {
	case "user_provision", "user_rotate_password":
		linuxUsername, password, err := r.st.UserProvisionInfo(ctx, j.TargetID)
		if err != nil {
			return err
		}
		if strings.TrimSpace(password) == "" {
			return fmt.Errorf("missing sftp password secret for user %s", j.TargetID)
		}
		if err := r.tc.Submit(ctx, tasks.Request{
			Type:   j.Type,
			Target: j.TargetID,
			Args: map[string]string{
				"linux_username": linuxUsername,
				"password":       password,
			},
		}); err != nil {
			return err
		}
		return r.st.ClearUserProvisionSecret(ctx, j.TargetID)

	case "site_create":
		info, err := r.st.SiteInfo(ctx, j.TargetID)
		if err != nil {
			return err
		}
		return r.tc.Submit(ctx, tasks.Request{
			Type:   "site_create",
			Target: j.TargetID,
			Args: map[string]string{
				"domain":         info.Domain,
				"linux_username": info.LinuxUsername,
			},
		})

	case "site_delete":
		info, err := r.st.SiteInfo(ctx, j.TargetID)
		if err != nil {
			return err
		}
		if err := r.tc.Submit(ctx, tasks.Request{
			Type:   "site_delete",
			Target: j.TargetID,
			Args: map[string]string{
				"domain":         info.Domain,
				"linux_username": info.LinuxUsername,
			},
		}); err != nil {
			return err
		}
		return r.st.DeleteSite(ctx, j.TargetID)

	case "ssl_issue", "ssl_renew":
		info, err := r.st.SiteInfo(ctx, j.TargetID)
		if err != nil {
			return err
		}
		if err := r.tc.Submit(ctx, tasks.Request{
			Type:   j.Type,
			Target: j.TargetID,
			Args: map[string]string{
				"provider":       "letsencrypt",
				"domain":         info.Domain,
				"linux_username": info.LinuxUsername,
			},
		}); err == nil {
			_ = r.st.SetSSLStatus(ctx, j.TargetID, "letsencrypt", "active", "", time.Now().UTC().Add(85*24*time.Hour))
			return nil
		} else {
			fallbackErr := r.tc.Submit(ctx, tasks.Request{
				Type:   j.Type,
				Target: j.TargetID,
				Args: map[string]string{
					"provider":       "zerossl",
					"domain":         info.Domain,
					"linux_username": info.LinuxUsername,
				},
			})
			if fallbackErr != nil {
				_ = r.st.SetSSLStatus(ctx, j.TargetID, "zerossl", "failed", fallbackErr.Error(), time.Time{})
				return fmt.Errorf("letsencrypt: %w; zerossl: %v", err, fallbackErr)
			}
			_ = r.st.SetSSLStatus(ctx, j.TargetID, "zerossl", "active", "", time.Now().UTC().Add(85*24*time.Hour))
			return nil
		}

	case "dns_apply":
		records, err := r.st.ZoneRecords(ctx, j.TargetID)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(records)
		if err != nil {
			return err
		}
		return r.tc.Submit(ctx, tasks.Request{
			Type:   "dns_apply",
			Target: j.TargetID,
			Args: map[string]string{
				"zone":         j.TargetID,
				"records_json": string(raw),
			},
		})

	case "dns_delete":
		zone := strings.TrimSpace(j.TargetID)
		if zone == "" {
			return fmt.Errorf("zone is required")
		}
		if err := r.tc.Submit(ctx, tasks.Request{
			Type:   "dns_delete",
			Target: zone,
			Args:   map[string]string{"zone": zone},
		}); err != nil {
			return err
		}
		return r.st.DeleteZone(ctx, zone)

	case "mail_apply":
		domains, mailboxes, aliases, err := r.st.MailState(ctx)
		if err != nil {
			return err
		}
		dRaw, err := json.Marshal(domains)
		if err != nil {
			return err
		}
		mRaw, err := json.Marshal(mailboxes)
		if err != nil {
			return err
		}
		aRaw, err := json.Marshal(aliases)
		if err != nil {
			return err
		}
		return r.tc.Submit(ctx, tasks.Request{
			Type:   "mail_apply",
			Target: "mail",
			Args: map[string]string{
				"domains_json":   string(dRaw),
				"mailboxes_json": string(mRaw),
				"aliases_json":   string(aRaw),
			},
		})

	case "backup_run":
		scope, err := r.st.BackupScope(ctx, j.TargetID)
		if err != nil {
			return err
		}
		_ = r.st.UpdateBackupStatus(ctx, j.TargetID, "running")
		if err := r.tc.Submit(ctx, tasks.Request{
			Type:   "backup_run",
			Target: j.TargetID,
			Args:   map[string]string{"scope": scope},
		}); err != nil {
			_ = r.st.UpdateBackupStatus(ctx, j.TargetID, "failed")
			return err
		}
		return r.st.UpdateBackupStatus(ctx, j.TargetID, "done")

	case "backup_restore":
		return r.tc.Submit(ctx, tasks.Request{Type: "backup_restore", Target: j.TargetID})

	case "db_create", "db_delete":
		info, err := r.st.DBInfo(ctx, j.TargetID)
		if err != nil {
			return err
		}
		engine := strings.ToLower(strings.TrimSpace(info.Engine))
		var agentType string
		switch engine {
		case "mariadb", "mysql":
			if j.Type == "db_create" {
				agentType = "db_create_mariadb"
			} else {
				agentType = "db_delete_mariadb"
			}
		case "postgres", "postgresql":
			if j.Type == "db_create" {
				agentType = "db_create_postgres"
			} else {
				agentType = "db_delete_postgres"
			}
		default:
			return fmt.Errorf("unsupported db engine: %s", info.Engine)
		}

		args := map[string]string{
			"db_name": info.Name,
			"db_user": info.Username,
		}
		if j.Type == "db_create" {
			args["db_password"] = info.Password
		}
		if err := r.tc.Submit(ctx, tasks.Request{Type: agentType, Target: j.TargetID, Args: args}); err != nil {
			return err
		}
		if j.Type == "db_delete" {
			return r.st.DeleteDatabaseMetadata(ctx, j.TargetID)
		}
		return nil
	}
	return fmt.Errorf("unsupported job type: %s", j.Type)
}
