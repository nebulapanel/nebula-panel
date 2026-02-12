package config

import (
	"os"
	"strings"
	"time"
)

type Config struct {
	AgentSocket       string
	AgentSharedSecret string
	SSLRenewInterval  time.Duration
	BackupInterval    time.Duration
	SSLRenewTargets   []string
	BackupScope       string
}

func Load() Config {
	return Config{
		AgentSocket:       envOr("NEBULA_AGENT_SOCKET", "/run/nebula-agent.sock"),
		AgentSharedSecret: envOr("NEBULA_AGENT_SHARED_SECRET", "change-me-in-prod"),
		SSLRenewInterval:  envDurationOr("NEBULA_SSL_RENEW_INTERVAL", 12*time.Hour),
		BackupInterval:    envDurationOr("NEBULA_BACKUP_INTERVAL", 24*time.Hour),
		SSLRenewTargets:   splitList(envOr("NEBULA_SSL_RENEW_TARGETS", "")),
		BackupScope:       envOr("NEBULA_BACKUP_SCOPE", "full"),
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
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
