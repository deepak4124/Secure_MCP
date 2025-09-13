# Makefile for MCP Security Framework

.PHONY: help install install-dev test test-cov lint format clean build docs

# Default target
help:
	@echo "MCP Security Framework - Available Commands:"
	@echo ""
	@echo "  install      Install the package in production mode"
	@echo "  install-dev  Install the package in development mode with dev dependencies"
	@echo "  test         Run all tests"
	@echo "  test-cov     Run tests with coverage report"
	@echo "  lint         Run linting checks"
	@echo "  format       Format code with black"
	@echo "  clean        Clean build artifacts and cache"
	@echo "  build        Build the package"
	@echo "  docs         Build documentation"
	@echo "  example      Run basic usage example"
	@echo ""

# Installation
install:
	pip install .

install-dev:
	pip install -e .[dev]

# Testing
test:
	pytest tests/ -v

test-cov:
	pytest tests/ --cov=mcp_security_framework --cov-report=html --cov-report=term

# Code quality
lint:
	flake8 mcp_security_framework/ tests/ examples/
	mypy mcp_security_framework/

format:
	black mcp_security_framework/ tests/ examples/

# Build and clean
build:
	python -m build

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

# Documentation
docs:
	cd docs && make html

# Examples
example:
	python examples/basic_usage.py

# Development setup
setup-dev: install-dev
	pre-commit install

# CI/CD helpers
ci-test: lint test-cov

# Docker helpers (if needed)
docker-build:
	docker build -t mcp-security-framework .

docker-test:
	docker run --rm mcp-security-framework pytest

# Release helpers
version:
	@python -c "import mcp_security_framework; print(mcp_security_framework.__version__)"

check-version:
	@python -c "import mcp_security_framework; print('Version:', mcp_security_framework.__version__)"

# Security checks
security-check:
	safety check
	bandit -r mcp_security_framework/

# Performance testing
perf-test:
	pytest tests/ -m performance -v

# Integration testing
integration-test:
	pytest tests/ -m integration -v

# All tests
test-all: lint test-cov security-check
