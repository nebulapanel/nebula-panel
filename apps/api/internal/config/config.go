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
	AgentSocket       string
	AgentSharedSecret string
	ACMEEmail         string
	SessionTTL        time.Duration
	AdminEmail        string
	AdminPassword     string
	AdminTOTPCode     string
	FilePermMask      os.FileMode
}

func Load() Config {
	return Config{
		HTTPAddr:          envOr("NEBULA_API_ADDR", ":8080"),
		DataRoot:          envOr("NEBULA_DATA_ROOT", "/var/lib/nebula-panel"),
		DatabaseURL:       envOr("NEBULA_DATABASE_URL", "postgres://nebula:nebula@127.0.0.1:5432/nebula?sslmode=disable"),
		AgentSocket:       envOr("NEBULA_AGENT_SOCKET", "/run/nebula-agent.sock"),
		AgentSharedSecret: envOr("NEBULA_AGENT_SHARED_SECRET", "change-me-in-prod"),
		ACMEEmail:         envOr("NEBULA_ACME_EMAIL", "admin@localhost"),
		SessionTTL:        envDurationOr("NEBULA_SESSION_TTL", 12*time.Hour),
		AdminEmail:        envOr("NEBULA_ADMIN_EMAIL", "admin@localhost"),
		AdminPassword:     envOr("NEBULA_ADMIN_PASSWORD", "admin123!"),
		AdminTOTPCode:     envOr("NEBULA_ADMIN_TOTP_CODE", "000000"),
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
