package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/nebula-panel/nebula/apps/agent/internal/config"
	"github.com/nebula-panel/nebula/apps/agent/internal/executor"
	"github.com/nebula-panel/nebula/apps/agent/internal/security"
)

type Server struct {
	cfg config.Config
	exe *executor.Executor
}

type taskRequest struct {
	Type      string            `json:"type"`
	Target    string            `json:"target"`
	Args      map[string]string `json:"args"`
	Timestamp time.Time         `json:"timestamp"`
}

func New(cfg config.Config) *Server {
	return &Server{cfg: cfg, exe: executor.New(cfg)}
}

func (s *Server) Run() error {
	if err := os.MkdirAll(filepath.Dir(s.cfg.SocketPath), 0o755); err != nil {
		return err
	}
	if err := os.RemoveAll(s.cfg.SocketPath); err != nil {
		return err
	}
	ln, err := net.Listen("unix", s.cfg.SocketPath)
	if err != nil {
		return err
	}
	if err := os.Chmod(s.cfg.SocketPath, 0o660); err != nil {
		return err
	}
	defer ln.Close()

	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.Recoverer)
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "service": "nebula-agent"})
	})
	r.Post("/v1/tasks", s.handleTask)

	httpServer := &http.Server{Handler: r}
	log.Printf("nebula-agent listening on unix://%s dry_run=%v", s.cfg.SocketPath, s.cfg.DryRun)
	return httpServer.Serve(ln)
}

func (s *Server) handleTask(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if len(payload) > 1<<20 {
		writeErr(w, http.StatusRequestEntityTooLarge, errors.New("payload too large"))
		return
	}
	if !security.VerifyHMAC(payload, r.Header.Get("X-Nebula-Signature"), s.cfg.SharedSecret) {
		writeErr(w, http.StatusUnauthorized, errors.New("invalid signature"))
		return
	}

	var req taskRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if req.Type == "" {
		writeErr(w, http.StatusBadRequest, errors.New("type is required"))
		return
	}
	if req.Timestamp.IsZero() || time.Since(req.Timestamp) > 5*time.Minute {
		writeErr(w, http.StatusUnauthorized, errors.New("stale request"))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.CmdTimeout)
	defer cancel()
	if err := s.exe.Execute(ctx, executor.Task{Type: req.Type, Target: req.Target, Args: req.Args}); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
}

func writeErr(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
