package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	SocketPath         string
	SharedSecret       string
	DryRun             bool
	CmdTimeout         time.Duration
	PowerDNSAPIURL     string
	PowerDNSAPIKey     string
	PowerDNSServerID   string
	ACMEWebroot        string
	ACMEEmail          string
	ZeroSSLEABKID      string
	ZeroSSLEABHMACKey  string
	GeneratedConfigDir string
}

func Load() Config {
	return Config{
		SocketPath:         envOr("NEBULA_AGENT_SOCKET", "/run/nebula-agent.sock"),
		SharedSecret:       envOr("NEBULA_AGENT_SHARED_SECRET", "change-me-in-prod"),
		DryRun:             envBoolOr("NEBULA_AGENT_DRY_RUN", true),
		CmdTimeout:         envDurationOr("NEBULA_AGENT_CMD_TIMEOUT", 10*time.Minute),
		PowerDNSAPIURL:     envOr("NEBULA_PDNS_API_URL", "http://127.0.0.1:8081"),
		PowerDNSAPIKey:     envOr("NEBULA_PDNS_API_KEY", ""),
		PowerDNSServerID:   envOr("NEBULA_PDNS_SERVER_ID", "localhost"),
		ACMEWebroot:        envOr("NEBULA_ACME_WEBROOT", "/var/www/nebula-acme"),
		ACMEEmail:          envOr("NEBULA_ACME_EMAIL", "admin@localhost"),
		ZeroSSLEABKID:      envOr("NEBULA_ZEROSSL_EAB_KID", ""),
		ZeroSSLEABHMACKey:  envOr("NEBULA_ZEROSSL_EAB_HMAC_KEY", ""),
		GeneratedConfigDir: envOr("NEBULA_GENERATED_CONFIG_DIR", "/etc/nebula-panel/generated"),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBoolOr(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
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
