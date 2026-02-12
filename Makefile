SHELL := /bin/bash

.PHONY: dev-up dev-down migrate lint test build run-api run-agent run-worker run-web fmt

dev-up:
	docker compose -f scripts/docker-compose.dev.yml up -d

dev-down:
	docker compose -f scripts/docker-compose.dev.yml down -v

migrate:
	set -a; [ -f .env ] && source .env; set +a; bash scripts/migrate.sh

lint:
	cd apps/api && go vet ./...
	cd apps/agent && go vet ./...
	cd apps/worker && go vet ./...
	cd apps/web && npm run lint

test:
	cd apps/api && go test ./...
	cd apps/agent && go test ./...
	cd apps/worker && go test ./...

build:
	cd apps/api && go build -o ../../bin/nebula-api ./cmd/api
	cd apps/agent && go build -o ../../bin/nebula-agent ./cmd/agent
	cd apps/worker && go build -o ../../bin/nebula-worker ./cmd/worker
	cd apps/web && npm run build

run-api:
	cd apps/api && set -a; [ -f ../../.env ] && source ../../.env; set +a; go run ./cmd/api

run-agent:
	cd apps/agent && set -a; [ -f ../../.env ] && source ../../.env; set +a; go run ./cmd/agent

run-worker:
	cd apps/worker && set -a; [ -f ../../.env ] && source ../../.env; set +a; go run ./cmd/worker

run-web:
	cd apps/web && set -a; [ -f ../../.env ] && source ../../.env; set +a; npm run dev

fmt:
	cd apps/api && gofmt -w $(shell find . -name '*.go')
	cd apps/agent && gofmt -w $(shell find . -name '*.go')
	cd apps/worker && gofmt -w $(shell find . -name '*.go')
