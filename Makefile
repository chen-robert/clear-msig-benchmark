CARGO_BUILD_SBF ?= $(shell scripts/detect-cargo-build-sbf.sh)

ANCHOR_SO := clear-msig-anchor/target/deploy/clear_msig_anchor.so
QUASAR_SO := clear-msig/target/deploy/clear_wallet.so

.PHONY: init bench build build-quasar clean check-toolchain

init:
	git submodule update --init --recursive

check-toolchain:
	@if [ -z "$(CARGO_BUILD_SBF)" ] || [ ! -x "$(CARGO_BUILD_SBF)" ]; then \
		echo "error: no cargo-build-sbf with platform-tools >= v1.52 found."; \
		echo "       install a newer Solana CLI, or:"; \
		echo "         make bench CARGO_BUILD_SBF=/path/to/bin/cargo-build-sbf"; \
		exit 1; \
	fi

build: check-toolchain
	cd clear-msig-anchor && $(abspath $(CARGO_BUILD_SBF)) --manifest-path programs/clear-msig-anchor/Cargo.toml --sbf-out-dir target/deploy

build-quasar: check-toolchain
	cd clear-msig && $(abspath $(CARGO_BUILD_SBF)) --manifest-path programs/clear-wallet/Cargo.toml --sbf-out-dir target/deploy

bench: build build-quasar
	cargo run --release --manifest-path bench/Cargo.toml -- $(ANCHOR_SO) $(QUASAR_SO)

clean:
	cd clear-msig-anchor && cargo clean
	rm -rf clear-msig-anchor/target/deploy clear-msig-anchor/target/sbpf-solana-solana
	rm -rf flamegraphs bench-report.html
