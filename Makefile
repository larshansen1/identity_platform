# Makefile for Identity Platform

BACKEND_DIR := backend
PYTHON := python3
PIP := $(PYTHON) -m pip

.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  install        Install backend dependencies (requires venv)"
	@echo "  dev-install    Install backend dev dependencies"
	@echo "  lint           Run Ruff linting"
	@echo "  format         Run Ruff formatter"
	@echo "  test           Run pytest"
	@echo "  typecheck      Run mypy"
	@echo "  coverage       Run tests with coverage"
	@echo "  radon          Run radon complexity checks"
	@echo "  vulture        Run vulture dead code analysis"
	@echo "  up             Start services with Podman Compose"
	@echo "  down           Stop services"
	@echo "  logs           View logs"
	@echo "  db-shell       Access PostgreSQL shell"

# ----------------------------
# Development
# ----------------------------

.PHONY: install
install:
	cd $(BACKEND_DIR) && $(PIP) install .

.PHONY: dev-install
dev-install:
	cd $(BACKEND_DIR) && $(PIP) install -e ".[dev]"

.PHONY: lint
lint:
	cd $(BACKEND_DIR) && ruff check .

.PHONY: format
format:
	cd $(BACKEND_DIR) && ruff format .

.PHONY: test
test:
	cd $(BACKEND_DIR) && pytest

.PHONY: typecheck
typecheck:
	cd $(BACKEND_DIR) && mypy src

.PHONY: coverage
coverage:
	cd $(BACKEND_DIR) && pytest --cov=src --cov-report=term-missing

.PHONY: radon
radon:
	cd $(BACKEND_DIR) && radon cc src -a -nb
	cd $(BACKEND_DIR) && radon mi src

.PHONY: vulture
vulture:
	cd $(BACKEND_DIR) && vulture src .vulture_whitelist.py

.PHONY: lock
lock:
	cd $(BACKEND_DIR) && pip-compile -o requirements.txt pyproject.toml
	cd $(BACKEND_DIR) && pip-compile --extra dev -o requirements-dev.txt pyproject.toml

# ----------------------------
# Podman Compose
# ----------------------------

.PHONY: up
up:
	podman-compose up -d

.PHONY: down
down:
	podman-compose down

.PHONY: logs
logs:
	podman-compose logs -f

.PHONY: db-shell
db-shell:
	podman-compose exec db psql -U postgres -d identity_platform
