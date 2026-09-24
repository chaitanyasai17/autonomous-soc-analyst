# ==============================================================================
# ASOC Makefile — convenience shortcuts (manual use only, nothing auto-executes)
# ==============================================================================

.PHONY: help
help:
	@echo "ASOC — available commands (run manually):"
	@echo "  make backend-install   Install backend dependencies (Part 2+)"
	@echo "  make backend-run       Run FastAPI dev server (Part 2+)"
	@echo "  make frontend-install  Install frontend dependencies (Part 13+)"
	@echo "  make frontend-run      Run Vite dev server (Part 13+)"
	@echo "  make docker-up         Start all services via Docker Compose (Part 15+)"
	@echo "  make docker-down       Stop all Docker Compose services (Part 15+)"

# The targets below are placeholders and will be wired up as each
# corresponding part is implemented. They intentionally do nothing yet.

backend-install:
	@echo "Backend dependency installation will be available after Part 2."

backend-run:
	@echo "Backend run command will be available after Part 2."

frontend-install:
	@echo "Frontend dependency installation will be available after Part 13."

frontend-run:
	@echo "Frontend run command will be available after Part 13."

docker-up:
	@echo "Docker Compose orchestration will be available after Part 15."

docker-down:
	@echo "Docker Compose orchestration will be available after Part 15."
