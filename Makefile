SHELL := /bin/bash
PYTHON := .venv/bin/python
PIP := .venv/bin/pip

.PHONY: install setup run-agent-hardened run-agent-vulnerable test-catalog test-gateway test-mcp test-all

install:
	python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

setup:
	$(PYTHON) setup_data.py

run-agent-hardened:
	$(PYTHON) run_agent.py --user medecin2 --ticket 2 --mode hardened

run-agent-vulnerable:
	$(PYTHON) run_agent.py --user medecin2 --ticket 2 --mode vulnerable

test-catalog:
	$(PYTHON) test_catalog.py

test-gateway:
	$(PYTHON) test_gateway.py

test-mcp:
	$(PYTHON) test_mcp.py

test-all: test-catalog test-gateway test-mcp
