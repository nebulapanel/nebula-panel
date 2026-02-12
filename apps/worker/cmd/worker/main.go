package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/nebula-panel/nebula/apps/worker/internal/config"
	"github.com/nebula-panel/nebula/apps/worker/internal/runner"
)

func main() {
	cfg := config.Load()
	r := runner.New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		cancel()
	}()

	if err := r.Run(ctx); err != nil {
		log.Fatalf("worker failed: %v", err)
	}
}
