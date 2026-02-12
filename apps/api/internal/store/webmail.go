package store

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nebula-panel/nebula/apps/api/internal/models"
)

func (s *Store) CreateWebmailSession(mailbox string, ttl time.Duration) (models.WebmailToken, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	localPart, domain, err := splitMailboxAddress(mailbox)
	if err != nil {
		return models.WebmailToken{}, err
	}

	var mailboxID string
	err = s.db.QueryRow(ctx, `
		SELECT m.id
		FROM mailboxes m
		JOIN mail_domains d ON d.id = m.mail_domain_id
		WHERE d.domain=$1 AND m.local_part=$2
	`, domain, localPart).Scan(&mailboxID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.WebmailToken{}, errors.New("mailbox not found")
		}
		return models.WebmailToken{}, err
	}

	token := models.WebmailToken{
		Token:     "wm_" + uuid.NewString(),
		Mailbox:   strings.ToLower(mailbox),
		ExpiresAt: time.Now().UTC().Add(ttl),
	}
	_, err = s.db.Exec(ctx, `
		INSERT INTO webmail_tokens (token, mailbox_id, expires_at)
		VALUES ($1, $2, $3)
	`, token.Token, mailboxID, token.ExpiresAt)
	if err != nil {
		return models.WebmailToken{}, err
	}

	_, _ = s.db.Exec(ctx, `
		INSERT INTO webmail_messages (id, mailbox_id, folder, from_addr, to_addr, subject, body)
		SELECT $1, $2, 'INBOX', 'welcome@nebula.local', $3, 'Welcome to Nebula Panel', 'Mailbox provisioned successfully.'
		WHERE NOT EXISTS (
			SELECT 1 FROM webmail_messages WHERE mailbox_id=$2 AND subject='Welcome to Nebula Panel'
		)
	`, "msg_"+uuid.NewString(), mailboxID, token.Mailbox)

	return token, nil
}

func (s *Store) GetWebmailSession(token string) (models.WebmailToken, bool) {
	ctx, cancel := s.ctx()
	defer cancel()

	var out models.WebmailToken
	var localPart, domain string
	err := s.db.QueryRow(ctx, `
		SELECT t.token, m.local_part, d.domain, t.expires_at
		FROM webmail_tokens t
		JOIN mailboxes m ON m.id = t.mailbox_id
		JOIN mail_domains d ON d.id = m.mail_domain_id
		WHERE t.token=$1 AND t.expires_at > NOW()
	`, token).Scan(&out.Token, &localPart, &domain, &out.ExpiresAt)
	if err != nil {
		return models.WebmailToken{}, false
	}
	out.Mailbox = localPart + "@" + domain
	return out, true
}

func (s *Store) mailboxIDForAddress(address string) (string, error) {
	ctx, cancel := s.ctx()
	defer cancel()
	localPart, domain, err := splitMailboxAddress(address)
	if err != nil {
		return "", err
	}
	var mailboxID string
	err = s.db.QueryRow(ctx, `
		SELECT m.id
		FROM mailboxes m
		JOIN mail_domains d ON d.id = m.mail_domain_id
		WHERE d.domain=$1 AND m.local_part=$2
	`, domain, localPart).Scan(&mailboxID)
	if err != nil {
		return "", err
	}
	return mailboxID, nil
}

func (s *Store) ListMailboxMessages(mailbox, folder string) []models.WebmailMessage {
	ctx, cancel := s.ctx()
	defer cancel()

	mailboxID, err := s.mailboxIDForAddress(mailbox)
	if err != nil {
		return nil
	}

	query := `
		SELECT id, folder, from_addr, to_addr, subject, body, created_at
		FROM webmail_messages
		WHERE mailbox_id=$1`
	args := []any{mailboxID}
	if strings.TrimSpace(folder) != "" {
		query += ` AND folder=$2`
		args = append(args, folder)
	}
	query += ` ORDER BY created_at DESC LIMIT 200`

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	out := make([]models.WebmailMessage, 0)
	for rows.Next() {
		var m models.WebmailMessage
		if err := rows.Scan(&m.ID, &m.Folder, &m.From, &m.To, &m.Subject, &m.Body, &m.CreatedAt); err == nil {
			out = append(out, m)
		}
	}
	return out
}

func (s *Store) SaveSentMessage(from, to, subject, body string) models.WebmailMessage {
	ctx, cancel := s.ctx()
	defer cancel()

	msg := models.WebmailMessage{
		ID:        "msg_" + uuid.NewString(),
		Folder:    "Sent",
		From:      strings.ToLower(strings.TrimSpace(from)),
		To:        strings.ToLower(strings.TrimSpace(to)),
		Subject:   subject,
		Body:      body,
		CreatedAt: time.Now().UTC(),
	}
	mailboxID, err := s.mailboxIDForAddress(msg.From)
	if err == nil {
		_ = s.db.QueryRow(ctx, `
			INSERT INTO webmail_messages (id, mailbox_id, folder, from_addr, to_addr, subject, body)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			RETURNING created_at
		`, msg.ID, mailboxID, msg.Folder, msg.From, msg.To, msg.Subject, msg.Body).Scan(&msg.CreatedAt)
		_, _ = s.db.Exec(ctx, `
			INSERT INTO mail_send_logs (id, mailbox_id, from_addr, to_addr, subject, status)
			VALUES ($1, $2, $3, $4, $5, 'queued')
		`, "send_"+uuid.NewString(), mailboxID, msg.From, msg.To, msg.Subject)
		return msg
	}

	_, _ = s.db.Exec(ctx, `
		INSERT INTO mail_send_logs (id, mailbox_id, from_addr, to_addr, subject, status)
		VALUES ($1, NULL, $2, $3, $4, 'queued')
	`, "send_"+uuid.NewString(), msg.From, msg.To, msg.Subject)
	return msg
}
