.PHONY: help install test test-cov lint format typecheck check demo demo-online doctor clean

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install:  ## Install the package with dev dependencies (editable)
	pip install -e ".[dev]"

test:  ## Run the test suite
	pytest -q

test-cov:  ## Run tests with a coverage report
	pytest -q --cov=sectools --cov-report=term-missing

lint:  ## Lint with ruff
	ruff check .

format:  ## Auto-format with ruff
	ruff format .

typecheck:  ## Type-check with mypy
	mypy src

check: lint typecheck test  ## Run all checks (lint + types + tests)

demo:  ## Generate sample data and run every offline tool
	bash examples/demo.sh

demo-online:  ## Like 'demo' but also run the network tools
	bash examples/demo.sh --online

doctor:  ## Show environment and dependency status
	sectools doctor

clean:  ## Remove caches and build artifacts
	rm -rf .pytest_cache .mypy_cache .ruff_cache build dist *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
