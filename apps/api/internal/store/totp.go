package store

import (
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type TOTPState struct {
	Enabled bool
}

func (s *Store) TOTPStatus(userID string) (TOTPState, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	var enabled bool
	err := s.db.QueryRow(ctx, `
		SELECT enabled
		FROM totp_secrets
		WHERE user_id=$1
	`, userID).Scan(&enabled)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// No row means not enabled.
			return TOTPState{Enabled: false}, nil
		}
		return TOTPState{}, err
	}
	return TOTPState{Enabled: enabled}, nil
}

func (s *Store) GetTOTPSecret(userID string) (secret string, enabled bool, ok bool) {
	ctx, cancel := s.ctx()
	defer cancel()

	var enc string
	if err := s.db.QueryRow(ctx, `
		SELECT secret_enc, enabled
		FROM totp_secrets
		WHERE user_id=$1
	`, userID).Scan(&enc, &enabled); err != nil {
		return "", false, false
	}

	secret = strings.TrimSpace(s.decodeSecret(enc))
	if secret == "" {
		return "", false, false
	}
	return secret, enabled, true
}

func (s *Store) UpsertTOTPSecret(userID string, secretBase32 string) error {
	ctx, cancel := s.ctx()
	defer cancel()

	secretBase32 = strings.TrimSpace(secretBase32)
	if secretBase32 == "" {
		return errors.New("secret is required")
	}

	_, err := s.db.Exec(ctx, `
		INSERT INTO totp_secrets (user_id, secret_enc, enabled, confirmed_at)
		VALUES ($1, $2, FALSE, NULL)
		ON CONFLICT (user_id) DO UPDATE
		SET secret_enc=EXCLUDED.secret_enc,
		    enabled=FALSE,
		    confirmed_at=NULL,
		    updated_at=NOW()
	`, userID, s.encodeSecret(secretBase32))
	return err
}

func (s *Store) EnableTOTP(userID string) error {
	ctx, cancel := s.ctx()
	defer cancel()

	_, err := s.db.Exec(ctx, `
		UPDATE totp_secrets
		SET enabled=TRUE,
		    confirmed_at=$2,
		    updated_at=NOW()
		WHERE user_id=$1
	`, userID, time.Now().UTC())
	return err
}

func (s *Store) DisableTOTP(userID string) error {
	ctx, cancel := s.ctx()
	defer cancel()

	_, err := s.db.Exec(ctx, `DELETE FROM totp_secrets WHERE user_id=$1`, userID)
	return err
}
