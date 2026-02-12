package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	HTTPAddr          string
	DataRoot          string
	DatabaseURL       string
	AppKey            string
	AgentSocket       string
	AgentSharedSecret string
	ACMEEmail         string
	PanelFQDN         string
	MailFQDN          string
	NS1FQDN           string
	NS2FQDN           string
	PublicIPv4        string
	SessionTTL        time.Duration
	AdminEmail        string
	AdminPassword     string
	FilePermMask      os.FileMode
}

func Load() Config {
	return Config{
		HTTPAddr:          envOr("NEBULA_API_ADDR", ":8080"),
		DataRoot:          envOr("NEBULA_DATA_ROOT", "/var/lib/nebula-panel"),
		DatabaseURL:       envOr("NEBULA_DATABASE_URL", "postgres://nebula:nebula@127.0.0.1:5432/nebula?sslmode=disable"),
		AppKey:            envOr("NEBULA_APP_KEY", ""),
		AgentSocket:       envOr("NEBULA_AGENT_SOCKET", "/run/nebula-agent.sock"),
		AgentSharedSecret: envOr("NEBULA_AGENT_SHARED_SECRET", "change-me-in-prod"),
		ACMEEmail:         envOr("NEBULA_ACME_EMAIL", "admin@localhost"),
		PanelFQDN:         envOr("NEBULA_PANEL_FQDN", ""),
		MailFQDN:          envOr("NEBULA_MAIL_FQDN", ""),
		NS1FQDN:           envOr("NEBULA_NS1_FQDN", ""),
		NS2FQDN:           envOr("NEBULA_NS2_FQDN", ""),
		PublicIPv4:        envOr("NEBULA_PUBLIC_IPV4", ""),
		SessionTTL:        envDurationOr("NEBULA_SESSION_TTL", 12*time.Hour),
		AdminEmail:        envOr("NEBULA_ADMIN_EMAIL", "admin@localhost"),
		// AdminPassword is only required during first bootstrap (when no admin exists yet).
		AdminPassword: envOr("NEBULA_ADMIN_PASSWORD", ""),
		FilePermMask:      envPermOr("NEBULA_FILE_PERM_MASK", 0o750),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envDurationOr(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return fallback
}

func envPermOr(key string, fallback os.FileMode) os.FileMode {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.ParseUint(v, 8, 32)
		if err == nil {
			return os.FileMode(n)
		}
	}
	return fallback
}
