package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nebula-panel/nebula/packages/lib/secrets"
)

type Store struct {
	appKey string
	db     *pgxpool.Pool
}

func New(ctx context.Context, databaseURL, appKey string) (*Store, error) {
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("connect db: %w", err)
	}
	if err := db.Ping(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}
	return &Store{appKey: appKey, db: db}, nil
}

func (s *Store) Close() {
	s.db.Close()
}

type Job struct {
	ID       string
	Type     string
	TargetID string
}

func (s *Store) ClaimNextJob(ctx context.Context, workerID string) (Job, bool, error) {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Job{}, false, err
	}
	defer tx.Rollback(ctx)

	var j Job
	err = tx.QueryRow(ctx, `
		SELECT id, type, target_id
		FROM jobs
		WHERE status='queued'
		ORDER BY created_at ASC
		FOR UPDATE SKIP LOCKED
		LIMIT 1
	`).Scan(&j.ID, &j.Type, &j.TargetID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Job{}, false, nil
		}
		return Job{}, false, err
	}

	_, err = tx.Exec(ctx, `
		UPDATE jobs
		SET status='running',
		    message='running',
		    updated_at=NOW(),
		    locked_at=NOW(),
		    locked_by=$2,
		    attempts=attempts+1
		WHERE id=$1
	`, j.ID, workerID)
	if err != nil {
		return Job{}, false, err
	}

	if err := s.appendJobEventTx(ctx, tx, j.ID, "running", "job claimed by "+workerID); err != nil {
		return Job{}, false, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Job{}, false, err
	}
	return j, true, nil
}

func (s *Store) MarkJobDone(ctx context.Context, jobID string, message string) error {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		UPDATE jobs
		SET status='done',
		    message=$2,
		    updated_at=NOW(),
		    finished_at=NOW()
		WHERE id=$1
	`, jobID, message)
	if err != nil {
		return err
	}
	if err := s.appendJobEventTx(ctx, tx, jobID, "done", message); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) MarkJobFailed(ctx context.Context, jobID string, message string) error {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		UPDATE jobs
		SET status='failed',
		    message=$2,
		    updated_at=NOW(),
		    finished_at=NOW()
		WHERE id=$1
	`, jobID, message)
	if err != nil {
		return err
	}
	if err := s.appendJobEventTx(ctx, tx, jobID, "failed", message); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) appendJobEventTx(ctx context.Context, tx pgx.Tx, jobID, status, message string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO job_events (id, job_id, status, message, created_at)
		VALUES ($1, $2, $3, $4, NOW())
	`, "je_"+uuid.NewString(), jobID, status, message)
	return err
}

type SiteInfo struct {
	Domain        string
	LinuxUsername string
}

func (s *Store) SiteInfo(ctx context.Context, siteID string) (SiteInfo, error) {
	var out SiteInfo
	err := s.db.QueryRow(ctx, `
		SELECT s.primary_domain, u.linux_username
		FROM sites s
		JOIN users u ON u.id = s.owner_user_id
		WHERE s.id=$1
	`, siteID).Scan(&out.Domain, &out.LinuxUsername)
	if err != nil {
		return SiteInfo{}, err
	}
	return out, nil
}

func (s *Store) DeleteSite(ctx context.Context, siteID string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM sites WHERE id=$1`, siteID)
	return err
}

type DNSRecord struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	TTL      int    `json:"ttl"`
	Priority int    `json:"priority,omitempty"`
}

func (s *Store) ZoneRecords(ctx context.Context, zone string) ([]DNSRecord, error) {
	rows, err := s.db.Query(ctx, `
		SELECT r.id, r.record_type, r.name, r.value, r.ttl, COALESCE(r.priority, 0)
		FROM dns_zones z
		JOIN dns_records r ON r.zone_id = z.id
		WHERE z.zone_name=$1
		ORDER BY r.created_at ASC
	`, zone)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]DNSRecord, 0)
	for rows.Next() {
		var rec DNSRecord
		if err := rows.Scan(&rec.ID, &rec.Type, &rec.Name, &rec.Value, &rec.TTL, &rec.Priority); err == nil {
			out = append(out, rec)
		}
	}
	return out, nil
}

func (s *Store) DeleteZone(ctx context.Context, zone string) error {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var zoneID string
	err = tx.QueryRow(ctx, `SELECT id FROM dns_zones WHERE zone_name=$1`, zone).Scan(&zoneID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM dns_records WHERE zone_id=$1`, zoneID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM dns_zones WHERE id=$1`, zoneID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type MailDomain struct {
	Domain string `json:"domain"`
}

type Mailbox struct {
	Address  string `json:"address"`
	Domain   string `json:"domain"`
	Password string `json:"password"`
}

type MailAlias struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

func (s *Store) MailState(ctx context.Context) ([]MailDomain, []Mailbox, []MailAlias, error) {
	dRows, err := s.db.Query(ctx, `SELECT domain FROM mail_domains ORDER BY domain ASC`)
	if err != nil {
		return nil, nil, nil, err
	}
	defer dRows.Close()
	domains := make([]MailDomain, 0)
	for dRows.Next() {
		var d MailDomain
		if err := dRows.Scan(&d.Domain); err == nil {
			domains = append(domains, d)
		}
	}

	mRows, err := s.db.Query(ctx, `
		SELECT d.domain, m.local_part, m.password_enc
		FROM mailboxes m
		JOIN mail_domains d ON d.id = m.mail_domain_id
		ORDER BY d.domain ASC, m.local_part ASC
	`)
	if err != nil {
		return nil, nil, nil, err
	}
	defer mRows.Close()

	mailboxes := make([]Mailbox, 0)
	for mRows.Next() {
		var domain, localPart, passwordEnc string
		if err := mRows.Scan(&domain, &localPart, &passwordEnc); err != nil {
			continue
		}
		password, err := secrets.DecryptAuto(s.appKey, passwordEnc)
		if err != nil {
			password = ""
		}
		mailboxes = append(mailboxes, Mailbox{
			Address:  localPart + "@" + domain,
			Domain:   domain,
			Password: password,
		})
	}

	aRows, err := s.db.Query(ctx, `
		SELECT a.source_addr, a.destination_addr
		FROM mail_aliases a
		JOIN mail_domains d ON d.id = a.mail_domain_id
		ORDER BY d.domain ASC, a.source_addr ASC
	`)
	if err != nil {
		return nil, nil, nil, err
	}
	defer aRows.Close()

	aliases := make([]MailAlias, 0)
	for aRows.Next() {
		var a MailAlias
		if err := aRows.Scan(&a.Source, &a.Destination); err == nil {
			aliases = append(aliases, a)
		}
	}

	return domains, mailboxes, aliases, nil
}

func (s *Store) SetSSLStatus(ctx context.Context, siteID, provider, status, errMsg string, expiresAt time.Time) error {
	if expiresAt.IsZero() {
		expiresAt = time.Now().UTC().Add(90 * 24 * time.Hour)
	}
	_, err := s.db.Exec(ctx, `
		INSERT INTO ssl_certificates (id, site_id, provider, status, expires_at, cert_pem, last_error)
		VALUES ($1, $2, $3, $4, $5, '', $6)
		ON CONFLICT (site_id) DO UPDATE
		SET provider=EXCLUDED.provider,
		    status=EXCLUDED.status,
		    expires_at=EXCLUDED.expires_at,
		    last_error=EXCLUDED.last_error,
		    updated_at=NOW()
	`, "ssl_"+uuid.NewString(), siteID, provider, status, expiresAt, errMsg)
	return err
}

func (s *Store) UpdateBackupStatus(ctx context.Context, backupID, status string) error {
	_, err := s.db.Exec(ctx, `UPDATE backups SET status=$2 WHERE id=$1`, backupID, status)
	return err
}

func (s *Store) BackupScope(ctx context.Context, backupID string) (string, error) {
	var scope string
	err := s.db.QueryRow(ctx, `SELECT scope FROM backups WHERE id=$1`, backupID).Scan(&scope)
	return scope, err
}

type DBInfo struct {
	Engine   string
	Name     string
	Username string
	Password string
}

func (s *Store) DBInfo(ctx context.Context, dbInstanceID string) (DBInfo, error) {
	var out DBInfo
	var passwordEnc string
	err := s.db.QueryRow(ctx, `
		SELECT i.engine, i.db_name, u.username, u.password_enc
		FROM db_instances i
		JOIN db_users u ON u.db_instance_id = i.id
		WHERE i.id=$1
		ORDER BY u.created_at ASC
		LIMIT 1
	`, dbInstanceID).Scan(&out.Engine, &out.Name, &out.Username, &passwordEnc)
	if err != nil {
		return DBInfo{}, err
	}
	pw, err := secrets.DecryptAuto(s.appKey, passwordEnc)
	if err == nil {
		out.Password = pw
	}
	return out, nil
}

func (s *Store) DeleteDatabaseMetadata(ctx context.Context, dbInstanceID string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM db_instances WHERE id=$1`, dbInstanceID)
	return err
}

func (s *Store) UserProvisionInfo(ctx context.Context, userID string) (linuxUsername string, password string, err error) {
	var passwordEnc string
	err = s.db.QueryRow(ctx, `
		SELECT linux_username, COALESCE(sftp_password_enc, '')
		FROM users
		WHERE id=$1
	`, userID).Scan(&linuxUsername, &passwordEnc)
	if err != nil {
		return "", "", err
	}
	if strings.TrimSpace(passwordEnc) == "" {
		return linuxUsername, "", nil
	}
	password, err = secrets.DecryptAuto(s.appKey, passwordEnc)
	if err != nil {
		password = ""
	}
	return linuxUsername, password, nil
}

func (s *Store) ClearUserProvisionSecret(ctx context.Context, userID string) error {
	_, err := s.db.Exec(ctx, `UPDATE users SET sftp_password_enc=NULL WHERE id=$1`, userID)
	return err
}
