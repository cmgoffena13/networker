format: lint
	cargo fmt

lint:
	cargo clippy

test:
	cargo test

compile:
	cargo build --release

run:
	cargo run