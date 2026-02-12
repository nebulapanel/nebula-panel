package store

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nebula-panel/nebula/apps/api/internal/models"
)

func (s *Store) CreateZone(zone string, records []models.DNSRecord) models.DNSZone {
	ctx, cancel := s.ctx()
	defer cancel()

	normZone := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	z := models.DNSZone{
		Zone:      normZone,
		Serial:    time.Now().UTC().Unix(),
		CreatedAt: time.Now().UTC(),
		Records:   records,
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return z
	}
	defer tx.Rollback(ctx)

	zoneID := "zone_" + uuid.NewString()
	err = tx.QueryRow(ctx, `
		INSERT INTO dns_zones (id, zone_name, soa_serial)
		VALUES ($1, $2, $3)
		RETURNING created_at
	`, zoneID, z.Zone, z.Serial).Scan(&z.CreatedAt)
	if err != nil {
		return z
	}

	for i := range z.Records {
		if z.Records[i].ID == "" {
			z.Records[i].ID = "r_" + uuid.NewString()
		}
		if z.Records[i].TTL <= 0 {
			z.Records[i].TTL = 3600
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO dns_records (id, zone_id, record_type, name, value, ttl, priority)
			VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, 0))
		`, z.Records[i].ID, zoneID, strings.ToUpper(z.Records[i].Type), z.Records[i].Name, z.Records[i].Value, z.Records[i].TTL, z.Records[i].Priority)
		if err != nil {
			return z
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return z
	}
	return z
}

func (s *Store) GetZone(zone string) (models.DNSZone, bool) {
	ctx, cancel := s.ctx()
	defer cancel()

	normZone := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	var zoneID string
	var z models.DNSZone
	err := s.db.QueryRow(ctx, `
		SELECT id, zone_name, soa_serial, created_at
		FROM dns_zones WHERE zone_name=$1
	`, normZone).Scan(&zoneID, &z.Zone, &z.Serial, &z.CreatedAt)
	if err != nil {
		return models.DNSZone{}, false
	}

	rows, err := s.db.Query(ctx, `
		SELECT id, record_type, name, value, ttl, COALESCE(priority, 0)
		FROM dns_records
		WHERE zone_id=$1
		ORDER BY created_at ASC
	`, zoneID)
	if err != nil {
		return models.DNSZone{}, false
	}
	defer rows.Close()

	recs := make([]models.DNSRecord, 0)
	for rows.Next() {
		var r models.DNSRecord
		if err := rows.Scan(&r.ID, &r.Type, &r.Name, &r.Value, &r.TTL, &r.Priority); err == nil {
			recs = append(recs, r)
		}
	}
	z.Records = recs
	return z, true
}

func (s *Store) ReplaceZoneRecords(zone string, records []models.DNSRecord) (models.DNSZone, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	normZone := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return models.DNSZone{}, err
	}
	defer tx.Rollback(ctx)

	var zoneID string
	err = tx.QueryRow(ctx, `SELECT id FROM dns_zones WHERE zone_name=$1`, normZone).Scan(&zoneID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.DNSZone{}, errors.New("zone not found")
		}
		return models.DNSZone{}, err
	}

	_, err = tx.Exec(ctx, `DELETE FROM dns_records WHERE zone_id=$1`, zoneID)
	if err != nil {
		return models.DNSZone{}, err
	}

	for i := range records {
		if records[i].ID == "" {
			records[i].ID = "r_" + uuid.NewString()
		}
		if records[i].TTL <= 0 {
			records[i].TTL = 3600
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO dns_records (id, zone_id, record_type, name, value, ttl, priority)
			VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, 0))
		`, records[i].ID, zoneID, strings.ToUpper(records[i].Type), records[i].Name, records[i].Value, records[i].TTL, records[i].Priority)
		if err != nil {
			return models.DNSZone{}, err
		}
	}

	_, err = tx.Exec(ctx, `UPDATE dns_zones SET soa_serial=$2, updated_at=NOW() WHERE id=$1`, zoneID, time.Now().UTC().Unix())
	if err != nil {
		return models.DNSZone{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return models.DNSZone{}, err
	}

	z, ok := s.GetZone(normZone)
	if !ok {
		return models.DNSZone{}, errors.New("zone not found")
	}
	return z, nil
}

func (s *Store) DeleteZoneRecord(zone, id string) (models.DNSZone, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	normZone := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return models.DNSZone{}, err
	}
	defer tx.Rollback(ctx)

	var zoneID string
	err = tx.QueryRow(ctx, `SELECT id FROM dns_zones WHERE zone_name=$1`, normZone).Scan(&zoneID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.DNSZone{}, errors.New("zone not found")
		}
		return models.DNSZone{}, err
	}
	_, err = tx.Exec(ctx, `DELETE FROM dns_records WHERE zone_id=$1 AND id=$2`, zoneID, id)
	if err != nil {
		return models.DNSZone{}, err
	}
	_, err = tx.Exec(ctx, `UPDATE dns_zones SET soa_serial=$2, updated_at=NOW() WHERE id=$1`, zoneID, time.Now().UTC().Unix())
	if err != nil {
		return models.DNSZone{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return models.DNSZone{}, err
	}

	z, ok := s.GetZone(normZone)
	if !ok {
		return models.DNSZone{}, errors.New("zone not found")
	}
	return z, nil
}

func (s *Store) CreateMailDomain(domain string) (models.MailDomain, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	normDomain := strings.ToLower(strings.TrimSpace(domain))
	md := models.MailDomain{Domain: normDomain, CreatedAt: time.Now().UTC()}
	err := s.db.QueryRow(ctx, `
		INSERT INTO mail_domains (id, domain)
		VALUES ($1, $2)
		ON CONFLICT (domain) DO UPDATE SET domain=EXCLUDED.domain
		RETURNING created_at
	`, "md_"+uuid.NewString(), normDomain).Scan(&md.CreatedAt)
	if err != nil {
		return models.MailDomain{}, err
	}
	return md, nil
}

func (s *Store) CreateMailbox(domain, localPart, password string, quotaMB int) (models.Mailbox, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	normDomain := strings.ToLower(strings.TrimSpace(domain))
	normLocal := strings.ToLower(strings.TrimSpace(localPart))
	if normLocal == "" {
		return models.Mailbox{}, errors.New("local part is required")
	}
	if quotaMB <= 0 {
		quotaMB = 2048
	}
	if password == "" {
		password = randomSecret(12)
	}

	var domainID string
	err := s.db.QueryRow(ctx, `SELECT id FROM mail_domains WHERE domain=$1`, normDomain).Scan(&domainID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.Mailbox{}, errors.New("mail domain not found")
		}
		return models.Mailbox{}, err
	}

	mb := models.Mailbox{
		ID:       "mb_" + uuid.NewString(),
		Domain:   normDomain,
		Address:  fmt.Sprintf("%s@%s", normLocal, normDomain),
		Password: password,
		QuotaMB:  quotaMB,
	}
	err = s.db.QueryRow(ctx, `
		INSERT INTO mailboxes (id, mail_domain_id, local_part, quota_mb, password_enc)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING created_at
	`, mb.ID, domainID, normLocal, mb.QuotaMB, encodeSecret(password)).Scan(&mb.CreatedAt)
	if err != nil {
		return models.Mailbox{}, err
	}
	return mb, nil
}

func (s *Store) DeleteMailbox(id string) {
	ctx, cancel := s.ctx()
	defer cancel()
	_, _ = s.db.Exec(ctx, `DELETE FROM mailboxes WHERE id=$1`, id)
}

func (s *Store) CreateAlias(domain, source, destination string) (models.MailAlias, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	normDomain := strings.ToLower(strings.TrimSpace(domain))
	a := models.MailAlias{
		ID:          "alias_" + uuid.NewString(),
		Domain:      normDomain,
		Source:      strings.ToLower(strings.TrimSpace(source)),
		Destination: strings.ToLower(strings.TrimSpace(destination)),
		CreatedAt:   time.Now().UTC(),
	}
	var domainID string
	err := s.db.QueryRow(ctx, `SELECT id FROM mail_domains WHERE domain=$1`, normDomain).Scan(&domainID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.MailAlias{}, errors.New("mail domain not found")
		}
		return models.MailAlias{}, err
	}
	err = s.db.QueryRow(ctx, `
		INSERT INTO mail_aliases (id, mail_domain_id, source_addr, destination_addr)
		VALUES ($1, $2, $3, $4)
		RETURNING created_at
	`, a.ID, domainID, a.Source, a.Destination).Scan(&a.CreatedAt)
	if err != nil {
		return models.MailAlias{}, err
	}
	return a, nil
}

func (s *Store) ListMailDomains() ([]models.MailDomain, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.Query(ctx, `SELECT domain, created_at FROM mail_domains ORDER BY domain ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]models.MailDomain, 0)
	for rows.Next() {
		var d models.MailDomain
		if err := rows.Scan(&d.Domain, &d.CreatedAt); err == nil {
			out = append(out, d)
		}
	}
	return out, nil
}

func (s *Store) ListMailboxes() ([]models.Mailbox, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.Query(ctx, `
		SELECT m.id, d.domain, m.local_part, m.quota_mb, m.password_enc, m.created_at
		FROM mailboxes m
		JOIN mail_domains d ON d.id = m.mail_domain_id
		ORDER BY d.domain ASC, m.local_part ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]models.Mailbox, 0)
	for rows.Next() {
		var m models.Mailbox
		var localPart string
		var passwordEnc string
		if err := rows.Scan(&m.ID, &m.Domain, &localPart, &m.QuotaMB, &passwordEnc, &m.CreatedAt); err == nil {
			m.Address = fmt.Sprintf("%s@%s", localPart, m.Domain)
			m.Password = decodeSecret(passwordEnc)
			out = append(out, m)
		}
	}
	return out, nil
}

func (s *Store) ListAliases() ([]models.MailAlias, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.Query(ctx, `
		SELECT a.id, d.domain, a.source_addr, a.destination_addr, a.created_at
		FROM mail_aliases a
		JOIN mail_domains d ON d.id = a.mail_domain_id
		ORDER BY d.domain ASC, a.source_addr ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]models.MailAlias, 0)
	for rows.Next() {
		var a models.MailAlias
		if err := rows.Scan(&a.ID, &a.Domain, &a.Source, &a.Destination, &a.CreatedAt); err == nil {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}
