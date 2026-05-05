.PHONY: setup run test test-coverage lint type-check format health clean install-hooks

# Setup: Install dependencies and initialize environment
setup:
	@echo "Setting up AgentGuard-X..."
	python -m pip install --upgrade pip
	pip install -r requirements.txt
	@echo "Installing pre-commit hooks..."
	pre-commit install
	@echo "✓ Setup complete"

# Run: Start the gateway service
run:
	@echo "Starting AgentGuard-X gateway..."
	uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Test: Run all tests
test:
	@echo "Running tests..."
	pytest tests/ -v --tb=short

# Test with coverage: Run tests with coverage report
test-coverage:
	@echo "Running tests with coverage..."
	pytest tests/ -v --cov=app --cov-report=html --cov-report=term

# Lint: Run ruff linter
lint:
	@echo "Running ruff linter..."
	ruff check . --show-source

# Type check: Run mypy type checker
type-check:
	@echo "Running mypy type checker..."
	mypy . --strict

# Format: Auto-format code with ruff
format:
	@echo "Formatting code with ruff..."
	ruff check . --fix

# Health: Check service health
health:
	@echo "Checking gateway health..."
	curl -s http://localhost:8000/health | python -m json.tool

# Clean: Remove build artifacts and caches
clean:
	@echo "Cleaning up..."
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name *.egg-info -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov/ 2>/dev/null || true
	rm -rf dist/ build/ 2>/dev/null || true
	@echo "✓ Clean complete"

# Install pre-commit hooks
install-hooks:
	@echo "Installing pre-commit hooks..."
	pre-commit install
	@echo "✓ Hooks installed"

# Run pre-commit on all files
pre-commit-all:
	@echo "Running pre-commit on all files..."
	pre-commit run --all-files

help:
	@echo "AgentGuard-X Makefile"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  setup              Install dependencies and pre-commit hooks"
	@echo "  run                Start the gateway service"
	@echo "  test               Run all tests"
	@echo "  test-coverage      Run tests with coverage report"
	@echo "  lint               Run ruff linter"
	@echo "  type-check         Run mypy type checker"
	@echo "  format             Auto-format code with ruff"
	@echo "  health             Check service health"
	@echo "  clean              Remove build artifacts and caches"
	@echo "  install-hooks      Install pre-commit hooks"
	@echo "  pre-commit-all     Run pre-commit on all files"
	@echo "  help               Show this help message"
