package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nebula-panel/nebula/apps/api/internal/config"
	apihttp "github.com/nebula-panel/nebula/apps/api/internal/http"
	"github.com/nebula-panel/nebula/apps/api/internal/store"
)

func main() {
	cfg := config.Load()

	st, err := store.New(cfg)
	if err != nil {
		log.Fatalf("store init failed: %v", err)
	}

	h := apihttp.NewServer(cfg, st)
	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           h.Router(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("nebula-api listening on %s", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server failed: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}
