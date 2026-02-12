package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nebula-panel/nebula/apps/api/internal/config"
	"github.com/nebula-panel/nebula/apps/api/internal/models"
	"github.com/nebula-panel/nebula/packages/lib/secrets"
	"github.com/nebula-panel/nebula/packages/lib/validate"
	"golang.org/x/crypto/bcrypt"
)

type Store struct {
	cfg config.Config
	db  *pgxpool.Pool
}

func New(cfg config.Config) (*Store, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	db, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("connect db: %w", err)
	}
	if err := db.Ping(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}

	s := &Store{cfg: cfg, db: db}
	if err := s.bootstrap(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) bootstrap(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `
		INSERT INTO roles (id, name) VALUES
		('role_admin', 'admin'),
		('role_user', 'user')
		ON CONFLICT (id) DO NOTHING`)
	if err != nil {
		return fmt.Errorf("bootstrap roles: %w", err)
	}

	var existingID string
	err = s.db.QueryRow(ctx, `SELECT id FROM users WHERE email=$1`, s.cfg.AdminEmail).Scan(&existingID)
	if err == nil {
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("bootstrap admin lookup: %w", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(s.cfg.AdminPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	adminID := "user_" + uuid.NewString()
	linuxUsername, err := validate.LinuxUsernameFromUserID(adminID)
	if err != nil {
		return fmt.Errorf("bootstrap admin username: %w", err)
	}
	_, err = s.db.Exec(ctx, `
		INSERT INTO users (id, email, role_id, password_hash, linux_username, sftp_enabled)
		VALUES ($1, $2, 'role_admin', $3, $4, TRUE)
	`, adminID, s.cfg.AdminEmail, string(hash), linuxUsername)
	if err != nil {
		return fmt.Errorf("bootstrap admin create: %w", err)
	}
	return nil
}

func (s *Store) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

func roleToID(role models.Role) string {
	if role == models.RoleAdmin {
		return "role_admin"
	}
	return "role_user"
}

func roleFromID(roleID string) models.Role {
	if roleID == "role_admin" {
		return models.RoleAdmin
	}
	return models.RoleUser
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func splitMailboxAddress(address string) (localPart, domain string, err error) {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(address)), "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", errors.New("invalid mailbox address")
	}
	return parts[0], parts[1], nil
}

func randomSecret(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

func (s *Store) encodeSecret(raw string) string {
	return secrets.EncryptOrBase64(s.cfg.AppKey, raw)
}

func (s *Store) decodeSecret(enc string) string {
	pt, err := secrets.DecryptAuto(s.cfg.AppKey, enc)
	if err != nil {
		return ""
	}
	return pt
}
