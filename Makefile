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