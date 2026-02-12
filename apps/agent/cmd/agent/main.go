package main

import (
	"log"

	"github.com/nebula-panel/nebula/apps/agent/internal/config"
	"github.com/nebula-panel/nebula/apps/agent/internal/server"
)

func main() {
	cfg := config.Load()
	s := server.New(cfg)
	if err := s.Run(); err != nil {
		log.Fatalf("nebula-agent failed: %v", err)
	}
}
