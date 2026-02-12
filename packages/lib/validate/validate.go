package validate

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	// Strict-ish FQDN validator: enforces at least one dot and sane label chars.
	domainRe = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+?$`)

	linuxUserRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

	dbIdentRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)
)

func NormalizeDomain(in string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(in))
	d = strings.TrimSuffix(d, ".")
	if d == "" {
		return "", errors.New("domain is required")
	}
	if len(d) > 253 {
		return "", errors.New("domain too long")
	}
	if !domainRe.MatchString(d) {
		return "", fmt.Errorf("invalid domain: %s", in)
	}
	return d, nil
}

func ValidateLinuxUsername(name string) error {
	u := strings.TrimSpace(name)
	if !linuxUserRe.MatchString(u) {
		return fmt.Errorf("invalid linux username: %q", name)
	}
	return nil
}

// LinuxUsernameFromUserID deterministically maps a panel user ID to a safe Linux username.
// Expected user ID format is "user_<uuid>".
func LinuxUsernameFromUserID(userID string) (string, error) {
	raw := strings.TrimSpace(userID)
	raw = strings.TrimPrefix(raw, "user_")
	// keep hex-ish characters for stability
	raw = strings.ToLower(raw)
	raw = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= '0' && r <= '9':
			return r
		default:
			return -1
		}
	}, raw)
	if raw == "" {
		return "", errors.New("user id is invalid")
	}
	if len(raw) > 8 {
		raw = raw[:8]
	}
	username := "nebula_" + raw
	if err := ValidateLinuxUsername(username); err != nil {
		return "", err
	}
	return username, nil
}

func ValidateDBIdentifier(id string) error {
	v := strings.ToLower(strings.TrimSpace(id))
	if v == "" {
		return errors.New("identifier is required")
	}
	if !dbIdentRe.MatchString(v) {
		return fmt.Errorf("invalid identifier: %q (use lowercase letters, digits, underscore; max 31 chars; must start with a letter)", id)
	}
	return nil
}

