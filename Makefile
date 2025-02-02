generate:
	@BPF_CFLAGS="" ; \
	if [ "$(BPF_ENABLE_LOG)" = "1" ]; then BPF_CFLAGS="$$BPF_CFLAGS -DENABLE_LOG"; fi ; \
	if [ "$(BPF_ENABLE_ROUTE_CACHE)" = "1" ]; then BPF_CFLAGS="$$BPF_CFLAGS -DENABLE_ROUTE_CACHE"; fi ; \
	BPF_CFLAGS=$$BPF_CFLAGS go generate -v ./cmd/...

docker-generate:
	@docker build -t eupf-dev -f dev/Dockerfile .
	@docker run --rm \
		-v $(PWD):/app \
		-w /app \
		-e BPF_ENABLE_LOG=$(BPF_ENABLE_LOG) \
		-e BPF_ENABLE_ROUTE_CACHE=$(BPF_ENABLE_ROUTE_CACHE) \
		eupf-dev go generate -v ./cmd/...

.PHONY: generate dev docker-dev docker-generate

dev:
	@bash -c "cd dev && docker compose up --build"

docker-dev:
	@docker build -t eupf-dev -f dev/Dockerfile .
	@docker run -it --rm \
		-v $(PWD):/app \
		-w /app \
		eupf-dev

# Helper function to run commands in Python virtual environment
define with_venv
	bash -c "source .venv/bin/activate && $(1)"
endef

pyenv:
	@python3 -m venv .venv
	@$(call with_venv, pip install -r pytest/requirements.txt)

.PHONY: pytest
pytest:
	@docker exec -it dev-eupf-1 python3 -m pytest -v -k 'not test_create_session_ueip' pytest/test_session.py

docker-exec:
	@docker exec -it dev-eupf-1 /bin/bash

loadtest:
	@docker exec -it dev-eupf-1 /bin/bash -c "cd /app && robot -v TCPREPLAY_LIMIT:2000000 -v TCPREPLAY_THREADS:8 ./robot/Loadtest.robot"
