package http

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nebula-panel/nebula/apps/api/internal/config"
	"github.com/nebula-panel/nebula/apps/api/internal/store"
)

func TestHealthz(t *testing.T) {
	cfg := config.Load()
	st, err := store.New(cfg)
	if err != nil {
		t.Skipf("store.New unavailable: %v", err)
	}
	s := NewServer(cfg, st)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	s.Router().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestLoginRequiresValidCredentials(t *testing.T) {
	cfg := config.Load()
	st, err := store.New(cfg)
	if err != nil {
		t.Skipf("store.New unavailable: %v", err)
	}
	s := NewServer(cfg, st)

	body, _ := json.Marshal(map[string]string{"email": "admin@localhost", "password": "wrong"})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.Router().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}
