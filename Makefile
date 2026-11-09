# Convenience targets. `make install` = per-user install: Rust binaries, browser host, GTK entry.
.PHONY: build test install
build:
	cd native/icp-agent && cargo build --release
	cd native/icp-shim && cargo build --release
test:
	.venv/bin/python -m unittest discover -s tests -q
	cd native/icp-agent && cargo test --release
install: build
	.venv/bin/icp setup
