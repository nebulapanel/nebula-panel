package store

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nebula-panel/nebula/apps/api/internal/models"
	"golang.org/x/crypto/bcrypt"
)

func (s *Store) CheckUserPassword(email, password string) (models.User, bool) {
	ctx, cancel := s.ctx()
	defer cancel()

	var u models.User
	var roleID string
	err := s.db.QueryRow(ctx, `
		SELECT id, email, role_id, password_hash, created_at
		FROM users WHERE email=$1
	`, email).Scan(&u.ID, &u.Email, &roleID, &u.PasswordHash, &u.CreatedAt)
	if err != nil {
		return models.User{}, false
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return models.User{}, false
	}
	u.Role = roleFromID(roleID)
	return u, true
}

func (s *Store) CreatePreAuth(userID string) string {
	ctx, cancel := s.ctx()
	defer cancel()

	token := uuid.NewString()
	_, err := s.db.Exec(ctx, `
		INSERT INTO auth_preauth_tokens (token, user_id, expires_at)
		VALUES ($1, $2, $3)
	`, token, userID, time.Now().UTC().Add(10*time.Minute))
	if err != nil {
		return ""
	}
	return token
}

func (s *Store) ConsumePreAuth(token string) (string, bool) {
	ctx, cancel := s.ctx()
	defer cancel()

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return "", false
	}
	defer tx.Rollback(ctx)

	var userID string
	err = tx.QueryRow(ctx, `
		SELECT user_id FROM auth_preauth_tokens
		WHERE token=$1 AND expires_at > NOW()
	`, token).Scan(&userID)
	if err != nil {
		return "", false
	}
	_, err = tx.Exec(ctx, `DELETE FROM auth_preauth_tokens WHERE token=$1`, token)
	if err != nil {
		return "", false
	}
	if err := tx.Commit(ctx); err != nil {
		return "", false
	}
	return userID, true
}

func (s *Store) CreateSession(userID string) (models.Session, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	var roleID string
	err := s.db.QueryRow(ctx, `SELECT role_id FROM users WHERE id=$1`, userID).Scan(&roleID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.Session{}, errors.New("user not found")
		}
		return models.Session{}, err
	}
	sess := models.Session{
		Token:     uuid.NewString(),
		UserID:    userID,
		Role:      roleFromID(roleID),
		ExpiresAt: time.Now().UTC().Add(s.cfg.SessionTTL),
	}
	_, err = s.db.Exec(ctx, `
		INSERT INTO sessions (token, user_id, expires_at)
		VALUES ($1, $2, $3)
	`, sess.Token, sess.UserID, sess.ExpiresAt)
	if err != nil {
		return models.Session{}, err
	}
	return sess, nil
}

func (s *Store) DeleteSession(token string) {
	ctx, cancel := s.ctx()
	defer cancel()
	_, _ = s.db.Exec(ctx, `DELETE FROM sessions WHERE token=$1`, token)
}

func (s *Store) ValidateSession(token string) (models.Session, bool) {
	ctx, cancel := s.ctx()
	defer cancel()

	var sess models.Session
	var roleID string
	err := s.db.QueryRow(ctx, `
		SELECT s.token, s.user_id, s.expires_at, u.role_id
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token=$1 AND s.expires_at > NOW()
	`, token).Scan(&sess.Token, &sess.UserID, &sess.ExpiresAt, &roleID)
	if err != nil {
		return models.Session{}, false
	}
	sess.Role = roleFromID(roleID)
	return sess, true
}
