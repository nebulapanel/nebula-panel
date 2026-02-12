package store

import (
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nebula-panel/nebula/apps/api/internal/models"
	"github.com/nebula-panel/nebula/packages/lib/validate"
	"golang.org/x/crypto/bcrypt"
)

func (s *Store) CreateUser(email, password string, role models.Role) (models.User, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return models.User{}, err
	}
	id := "user_" + uuid.NewString()
	linuxUsername, err := validate.LinuxUsernameFromUserID(id)
	if err != nil {
		return models.User{}, err
	}
	u := models.User{
		ID:            id,
		Email:         email,
		Role:          role,
		LinuxUsername: linuxUsername,
		SFTPEnabled:   true,
		PasswordHash:  string(hash),
	}
	err = s.db.QueryRow(ctx, `
		INSERT INTO users (id, email, role_id, password_hash, linux_username, sftp_enabled)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING created_at
	`, u.ID, u.Email, roleToID(u.Role), u.PasswordHash, u.LinuxUsername, u.SFTPEnabled).Scan(&u.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return models.User{}, errors.New("email already exists")
		}
		return models.User{}, err
	}
	return u, nil
}

func (s *Store) ListUsers() []models.User {
	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.Query(ctx, `
		SELECT id, email, role_id, linux_username, sftp_enabled, created_at
		FROM users
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	res := make([]models.User, 0)
	for rows.Next() {
		var u models.User
		var roleID string
		if err := rows.Scan(&u.ID, &u.Email, &roleID, &u.LinuxUsername, &u.SFTPEnabled, &u.CreatedAt); err != nil {
			continue
		}
		u.Role = roleFromID(roleID)
		res = append(res, u)
	}
	return res
}

func (s *Store) GetUser(id string) (models.User, bool) {
	ctx, cancel := s.ctx()
	defer cancel()

	var u models.User
	var roleID string
	err := s.db.QueryRow(ctx, `
		SELECT id, email, role_id, linux_username, sftp_enabled, created_at
		FROM users
		WHERE id=$1
	`, id).Scan(&u.ID, &u.Email, &roleID, &u.LinuxUsername, &u.SFTPEnabled, &u.CreatedAt)
	if err != nil {
		return models.User{}, false
	}
	u.Role = roleFromID(roleID)
	return u, true
}

func (s *Store) UpdateUser(id string, role models.Role) (models.User, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	var u models.User
	var roleID string
	err := s.db.QueryRow(ctx, `
		UPDATE users
		SET role_id=$1
		WHERE id=$2
		RETURNING id, email, role_id, linux_username, sftp_enabled, created_at
	`, roleToID(role), id).Scan(&u.ID, &u.Email, &roleID, &u.LinuxUsername, &u.SFTPEnabled, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.User{}, errors.New("user not found")
		}
		return models.User{}, err
	}
	u.Role = roleFromID(roleID)
	return u, nil
}

func (s *Store) DeleteUser(id string) {
	ctx, cancel := s.ctx()
	defer cancel()
	_, _ = s.db.Exec(ctx, `DELETE FROM users WHERE id=$1`, id)
}

func (s *Store) SetUserSFTPSecret(userID, password string) error {
	ctx, cancel := s.ctx()
	defer cancel()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `
		UPDATE users
		SET sftp_password_enc=$2, sftp_password_hash=$3
		WHERE id=$1
	`, userID, s.encodeSecret(password), string(hash))
	return err
}

func (s *Store) CreateSite(name, domain, ownerID string) (models.Site, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	var linuxUsername string
	if err := s.db.QueryRow(ctx, `SELECT linux_username FROM users WHERE id=$1`, ownerID).Scan(&linuxUsername); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.Site{}, errors.New("owner not found")
		}
		return models.Site{}, err
	}
	normDomain, err := validate.NormalizeDomain(domain)
	if err != nil {
		return models.Site{}, err
	}
	domain = normDomain

	site := models.Site{
		ID:       "site_" + uuid.NewString(),
		Name:     name,
		Domain:   domain,
		OwnerID:  ownerID,
		RootPath: filepath.Join("/home", linuxUsername, "web", domain, "public_html"),
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return models.Site{}, err
	}
	defer tx.Rollback(ctx)

	err = tx.QueryRow(ctx, `
		INSERT INTO sites (id, owner_user_id, name, primary_domain, root_path)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING created_at
	`, site.ID, site.OwnerID, site.Name, site.Domain, site.RootPath).Scan(&site.CreatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "sites_owner_user_id_fkey") {
			return models.Site{}, errors.New("owner not found")
		}
		return models.Site{}, err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO site_domains (id, site_id, domain, is_primary)
		VALUES ($1, $2, $3, TRUE)
	`, "sdom_"+uuid.NewString(), site.ID, site.Domain)
	if err != nil {
		return models.Site{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return models.Site{}, err
	}
	return site, nil
}

func (s *Store) GetSite(id string) (models.Site, bool) {
	ctx, cancel := s.ctx()
	defer cancel()

	var site models.Site
	err := s.db.QueryRow(ctx, `
		SELECT id, name, primary_domain, owner_user_id, root_path, created_at
		FROM sites WHERE id=$1
	`, id).Scan(&site.ID, &site.Name, &site.Domain, &site.OwnerID, &site.RootPath, &site.CreatedAt)
	if err != nil {
		return models.Site{}, false
	}
	return site, true
}

func (s *Store) ListSites() []models.Site {
	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.Query(ctx, `
		SELECT id, name, primary_domain, owner_user_id, root_path, created_at
		FROM sites
		ORDER BY created_at DESC
		LIMIT 500
	`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	out := make([]models.Site, 0)
	for rows.Next() {
		var site models.Site
		if err := rows.Scan(&site.ID, &site.Name, &site.Domain, &site.OwnerID, &site.RootPath, &site.CreatedAt); err == nil {
			out = append(out, site)
		}
	}
	return out
}

func (s *Store) ListSitesForOwner(ownerID string) []models.Site {
	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.Query(ctx, `
		SELECT id, name, primary_domain, owner_user_id, root_path, created_at
		FROM sites
		WHERE owner_user_id=$1
		ORDER BY created_at DESC
		LIMIT 500
	`, ownerID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	out := make([]models.Site, 0)
	for rows.Next() {
		var site models.Site
		if err := rows.Scan(&site.ID, &site.Name, &site.Domain, &site.OwnerID, &site.RootPath, &site.CreatedAt); err == nil {
			out = append(out, site)
		}
	}
	return out
}

func (s *Store) DeleteSite(id string) {
	ctx, cancel := s.ctx()
	defer cancel()
	_, _ = s.db.Exec(ctx, `DELETE FROM sites WHERE id=$1`, id)
}

func (s *Store) ListDatabases(siteID string) []models.Database {
	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.Query(ctx, `
		SELECT i.id, i.site_id, i.engine, i.db_name, COALESCE(u.username, ''), i.created_at
		FROM db_instances i
		LEFT JOIN LATERAL (
			SELECT username FROM db_users
			WHERE db_instance_id=i.id
			ORDER BY created_at ASC
			LIMIT 1
		) u ON TRUE
		WHERE i.site_id=$1
		ORDER BY i.created_at DESC
		LIMIT 500
	`, siteID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	out := make([]models.Database, 0)
	for rows.Next() {
		var d models.Database
		if err := rows.Scan(&d.ID, &d.SiteID, &d.Engine, &d.Name, &d.Username, &d.CreatedAt); err == nil {
			out = append(out, d)
		}
	}
	return out
}

func (s *Store) CreateDatabase(siteID, engine, name, username string) (models.Database, string, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	port := 3306
	if strings.EqualFold(engine, "postgres") || strings.EqualFold(engine, "postgresql") {
		port = 5432
	}
	password := randomSecret(18)
	dbModel := models.Database{
		ID:       "db_" + uuid.NewString(),
		SiteID:   siteID,
		Engine:   strings.ToLower(engine),
		Name:     name,
		Username: username,
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return models.Database{}, "", err
	}
	defer tx.Rollback(ctx)

	err = tx.QueryRow(ctx, `
		INSERT INTO db_instances (id, site_id, engine, db_name, host, port)
		VALUES ($1, $2, $3, $4, 'localhost', $5)
		RETURNING created_at
	`, dbModel.ID, dbModel.SiteID, dbModel.Engine, dbModel.Name, port).Scan(&dbModel.CreatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "db_instances_site_id_fkey") {
			return models.Database{}, "", errors.New("site not found")
		}
		return models.Database{}, "", err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO db_users (id, db_instance_id, username, password_enc)
		VALUES ($1, $2, $3, $4)
	`, "dbu_"+uuid.NewString(), dbModel.ID, dbModel.Username, s.encodeSecret(password))
	if err != nil {
		return models.Database{}, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return models.Database{}, "", err
	}
	return dbModel, password, nil
}

func (s *Store) DeleteDatabase(id string) {
	ctx, cancel := s.ctx()
	defer cancel()
	_, _ = s.db.Exec(ctx, `DELETE FROM db_instances WHERE id=$1`, id)
}

func (s *Store) DatabaseExists(id string) bool {
	ctx, cancel := s.ctx()
	defer cancel()
	var exists bool
	_ = s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM db_instances WHERE id=$1)`, id).Scan(&exists)
	return exists
}

func (s *Store) SetSSLStatus(siteID, provider, status, errMsg string, expires time.Time) models.SSLStatus {
	ctx, cancel := s.ctx()
	defer cancel()

	if expires.IsZero() {
		expires = time.Now().UTC().Add(90 * 24 * time.Hour)
	}
	var st models.SSLStatus
	st.SiteID = siteID
	st.Provider = provider
	st.Status = status
	st.LastError = errMsg
	st.ExpiresAt = expires
	st.UpdatedAt = time.Now().UTC()

	_ = s.db.QueryRow(ctx, `
		INSERT INTO ssl_certificates (id, site_id, provider, status, expires_at, cert_pem, last_error)
		VALUES ($1, $2, $3, $4, $5, '', $6)
		ON CONFLICT (site_id) DO UPDATE
		SET provider=EXCLUDED.provider,
		    status=EXCLUDED.status,
		    expires_at=EXCLUDED.expires_at,
		    last_error=EXCLUDED.last_error,
		    updated_at=NOW()
		RETURNING COALESCE(cert_pem, ''), updated_at
	`, "ssl_"+uuid.NewString(), siteID, provider, status, expires, errMsg).Scan(&st.Certificate, &st.UpdatedAt)
	return st
}

func (s *Store) GetSSLStatus(siteID string) (models.SSLStatus, bool) {
	ctx, cancel := s.ctx()
	defer cancel()

	var st models.SSLStatus
	st.SiteID = siteID
	err := s.db.QueryRow(ctx, `
		SELECT provider, status, COALESCE(expires_at, NOW()), COALESCE(last_error, ''), updated_at, COALESCE(cert_pem, '')
		FROM ssl_certificates WHERE site_id=$1
	`, siteID).Scan(&st.Provider, &st.Status, &st.ExpiresAt, &st.LastError, &st.UpdatedAt, &st.Certificate)
	if err != nil {
		return models.SSLStatus{}, false
	}
	return st, true
}

func (s *Store) CreateBackup(scope string) models.Backup {
	ctx, cancel := s.ctx()
	defer cancel()

	b := models.Backup{
		ID:         "backup_" + uuid.NewString(),
		Scope:      scope,
		Status:     "queued",
		BucketPath: "s3://nebula-backups/" + time.Now().UTC().Format("2006/01/02") + "/" + uuid.NewString() + ".tar.zst.enc",
	}
	_ = s.db.QueryRow(ctx, `
		INSERT INTO backups (id, scope, status, destination_uri)
		VALUES ($1, $2, $3, $4)
		RETURNING created_at
	`, b.ID, b.Scope, b.Status, b.BucketPath).Scan(&b.CreatedAt)
	return b
}

func (s *Store) ListBackups() []models.Backup {
	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.Query(ctx, `
		SELECT id, scope, status, destination_uri, created_at
		FROM backups ORDER BY created_at DESC
	`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	out := make([]models.Backup, 0)
	for rows.Next() {
		var b models.Backup
		if err := rows.Scan(&b.ID, &b.Scope, &b.Status, &b.BucketPath, &b.CreatedAt); err == nil {
			out = append(out, b)
		}
	}
	return out
}

func (s *Store) GetBackup(id string) (models.Backup, bool) {
	ctx, cancel := s.ctx()
	defer cancel()

	var b models.Backup
	err := s.db.QueryRow(ctx, `
		SELECT id, scope, status, destination_uri, created_at
		FROM backups WHERE id=$1
	`, id).Scan(&b.ID, &b.Scope, &b.Status, &b.BucketPath, &b.CreatedAt)
	if err != nil {
		return models.Backup{}, false
	}
	return b, true
}

func (s *Store) CreateJob(jobType, targetID, status string) models.Job {
	ctx, cancel := s.ctx()
	defer cancel()

	j := models.Job{ID: "job_" + uuid.NewString(), Type: jobType, Status: status, TargetID: targetID}
	_ = s.db.QueryRow(ctx, `
		INSERT INTO jobs (id, type, status, target_id)
		VALUES ($1, $2, $3, $4)
		RETURNING created_at
	`, j.ID, j.Type, j.Status, j.TargetID).Scan(&j.CreatedAt)
	return j
}

func (s *Store) UpdateJobStatus(id, status, message string) {
	ctx, cancel := s.ctx()
	defer cancel()

	if status == "done" || status == "failed" {
		_, _ = s.db.Exec(ctx, `
			UPDATE jobs
			SET status=$2, message=$3, finished_at=NOW()
			WHERE id=$1
		`, id, status, message)
		return
	}
	_, _ = s.db.Exec(ctx, `
		UPDATE jobs
		SET status=$2, message=$3
		WHERE id=$1
	`, id, status, message)
}

func (s *Store) GetJob(id string) (models.Job, bool) {
	ctx, cancel := s.ctx()
	defer cancel()

	var j models.Job
	err := s.db.QueryRow(ctx, `
		SELECT id, type, status, target_id, COALESCE(message, ''), created_at, COALESCE(finished_at, 'epoch'::timestamptz)
		FROM jobs WHERE id=$1
	`, id).Scan(&j.ID, &j.Type, &j.Status, &j.TargetID, &j.Message, &j.CreatedAt, &j.FinishedAt)
	if err != nil {
		return models.Job{}, false
	}
	if j.FinishedAt.Equal(time.Unix(0, 0).UTC()) {
		j.FinishedAt = time.Time{}
	}
	return j, true
}

func (s *Store) ListJobs(limit int) []models.Job {
	ctx, cancel := s.ctx()
	defer cancel()

	if limit <= 0 || limit > 200 {
		limit = 50
	}

	rows, err := s.db.Query(ctx, `
		SELECT id, type, status, target_id, COALESCE(message, ''), created_at, COALESCE(finished_at, 'epoch'::timestamptz)
		FROM jobs
		ORDER BY created_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()

	out := make([]models.Job, 0)
	for rows.Next() {
		var j models.Job
		if err := rows.Scan(&j.ID, &j.Type, &j.Status, &j.TargetID, &j.Message, &j.CreatedAt, &j.FinishedAt); err == nil {
			if j.FinishedAt.Equal(time.Unix(0, 0).UTC()) {
				j.FinishedAt = time.Time{}
			}
			out = append(out, j)
		}
	}
	return out
}

func (s *Store) ListJobEvents(jobID string) []models.JobEvent {
	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.Query(ctx, `
		SELECT id, job_id, status, COALESCE(message, ''), created_at
		FROM job_events
		WHERE job_id=$1
		ORDER BY created_at ASC
		LIMIT 1000
	`, jobID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	out := make([]models.JobEvent, 0)
	for rows.Next() {
		var ev models.JobEvent
		if err := rows.Scan(&ev.ID, &ev.JobID, &ev.Status, &ev.Message, &ev.CreatedAt); err == nil {
			out = append(out, ev)
		}
	}
	return out
}

func (s *Store) AddAudit(actor, action, target, summary string) {
	ctx, cancel := s.ctx()
	defer cancel()
	_, _ = s.db.Exec(ctx, `
		INSERT INTO audit_logs (id, actor_user_id, action, target, summary)
		VALUES ($1, NULLIF($2, ''), $3, $4, $5)
	`, "audit_"+uuid.NewString(), actor, action, target, summary)
}

func (s *Store) ListAudit() []models.AuditLog {
	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.Query(ctx, `
		SELECT id, COALESCE(actor_user_id, ''), action, target, summary, created_at
		FROM audit_logs
		ORDER BY created_at DESC
		LIMIT 500
	`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	out := make([]models.AuditLog, 0)
	for rows.Next() {
		var a models.AuditLog
		if err := rows.Scan(&a.ID, &a.ActorID, &a.Action, &a.Target, &a.Summary, &a.CreatedAt); err == nil {
			out = append(out, a)
		}
	}
	return out
}
