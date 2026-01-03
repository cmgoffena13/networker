.PHONY: format lint test install setup upgrade seed docs compile

format: lint
	uv run -- ruff format

lint:
	uv run -- ruff check --fix

test:
	uv run -- pytest -v -n auto

install:
	uv sync --frozen --compile-bytecode --all-extras

setup:
	uv sync --frozen --compile-bytecode --all-extras
	uv run -- pre-commit install --install-hooks

upgrade:
	uv sync --upgrade --all-extras

seed:
	uv run -- python -m src.seeds.main

docs:
	PYTHONPATH=. uv run -- typer src.cli.main utils docs --name networker --output docs/cli.md

compile: create-base-db
	uv run -- nuitka --onefile src/cli/main.py --output-filename=networker --python-flag="no_warnings" --noinclude-data-files=src/tests/* --output-dir=dist/

create-base-db:
	uv run -- python -m src.database.db create_base_db

update-inferences:
	uv run -- python -m src.database.db update_inferences