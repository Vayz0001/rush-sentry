.PHONY: help setup scan lab-up lab-down notify test lint

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n",$$1,$$2}'

setup: ## Wire cross-agent shims (symlinks)
	./setup.sh

scan: ## Run all scanners on the current repo (SARIF)
	./bin/toolkit scan all --target . --format sarif

lab-up: ## Bring up the isolated vulnerable-app lab
	./bin/toolkit lab up

lab-down: ## Tear down the lab
	./bin/toolkit lab down

notify: ## Run threat-intel cross-reference + webhook
	./bin/toolkit notify run

test: ## Run wrapper/script unit tests
	@python3 -c "import pytest" 2>/dev/null && python3 -m pytest tests/ -q || echo "pytest not installed: pip install pytest"

lint: ## Lint shell + python
	@command -v shellcheck >/dev/null && shellcheck bin/toolkit scanners/*/run.sh 2>/dev/null || echo "shellcheck not installed"
