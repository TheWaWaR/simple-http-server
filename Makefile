fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --all --tests --all-features -- -F warnings

test: export RUST_BACKTRACE := full
test:
	RUSTFLAGS='-F warnings'  cargo test --all --all-features

ci: fmt clippy example test
	git diff --exit-code Cargo.lock
