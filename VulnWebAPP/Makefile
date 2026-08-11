SHELL := /bin/sh

.PHONY: help backend frontend up down logs build clean

help:
	@echo "Available targets:"
	@echo "  make backend   - run the Go API locally"
	@echo "  make frontend  - run the React frontend locally"
	@echo "  make up        - start both services with Docker Compose"
	@echo "  make down      - stop the Docker Compose stack"
	@echo "  make logs      - follow Docker Compose logs"
	@echo "  make build     - build both Docker images"
	@echo "  make clean     - remove Docker Compose resources"

backend:
	cd backend && go run .

frontend:
	cd frontend && npm install && npm run dev

up:
	docker compose up --build

down:
	docker compose down

logs:
	docker compose logs -f

build:
	docker compose build

clean:
	docker compose down --volumes --remove-orphans
