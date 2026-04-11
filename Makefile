format: lint
	cargo fmt

lint:
	cargo clippy

test:
	cargo test

check:
	cargo check

compile:
	cargo build --release

run:
	cargo run