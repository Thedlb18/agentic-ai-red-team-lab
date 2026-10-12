SHELL := /bin/bash
PYTHON := .venv/bin/python
PIP := .venv/bin/pip

MODEL ?= LFM2.5
N ?= 1
MODE ?= both
FAMILIES ?= all
CASES ?=
PROMPTS ?= full
MCP ?= 0

BATCH_ARGS = --n $(N) --model $(MODEL) --mode $(MODE) --prompts $(PROMPTS)
ifneq ($(FAMILIES),all)
BATCH_ARGS += --families $(FAMILIES)
endif
ifneq ($(CASES),)
BATCH_ARGS += --cases $(CASES)
endif
ifeq ($(MCP),1)
BATCH_ARGS += --mcp
endif

.PHONY: help install setup run-agent run-agent-hardened run-agent-vulnerable \
	test-catalog test-gateway test-mcp test-tool-calling test-batch \
	test-batch-scripted test-batch-ollama test-all

help:
	@echo "Installation et préparation : install, setup"
	@echo "Lancer l'agent : run-agent, run-agent-hardened, run-agent-vulnerable"
	@echo "Tests locaux : test-catalog, test-gateway, test-mcp"
	@echo "Tests modèle réel : test-tool-calling (Ollama requis)"
	@echo "Campagnes : test-batch-scripted (sans Ollama), test-batch-ollama (Ollama requis), test-batch"
	@echo "Suite complète hors Ollama : test-all"
	@echo "Paramètres campagne : N=1 MODEL=LFM2.5 MODE=both FAMILIES=all CASES= PROMPTS=full MCP=0"

install:
	python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

setup:
	$(PYTHON) setup_data.py

run-agent: run-agent-hardened

run-agent-hardened:
	$(PYTHON) run_agent.py --user medecin2 --ticket 2 --mode hardened --model $(MODEL)

run-agent-vulnerable:
	$(PYTHON) run_agent.py --user medecin2 --ticket 2 --mode vulnerable --model $(MODEL)

test-catalog:
	$(PYTHON) test_catalog.py

test-gateway:
	$(PYTHON) Test_gateway.py

test-mcp:
	$(PYTHON) test_mcp.py

test-tool-calling:
	$(PYTHON) test_tool_calling.py $(MODEL)

test-batch:
	$(PYTHON) run_batch.py $(BATCH_ARGS)

test-batch-scripted:
	$(PYTHON) run_batch.py --n $(N) --model scripted --mode both --prompts $(PROMPTS) --mcp

test-batch-ollama:
	$(PYTHON) run_batch.py --n $(N) --model $(MODEL) --mode $(MODE) --prompts $(PROMPTS) --mcp

test-all: test-catalog test-gateway test-mcp test-batch-scripted
