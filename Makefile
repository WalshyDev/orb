# Default target
help:
	@echo "Orb - Makefile Commands"
	@echo ""
	@echo "Build Commands:"
	@echo "  make build              - Build debug version"
	@echo "  make release            - Build optimized release version"
	@echo ""
	@echo "Test Commands:"
	@echo "  make test               - Run all tests"
	@echo "  make test-e2e           - Run e2e tests (requires internet)"
	@echo "  make coverage           - Generate HTML coverage report"
	@echo ""
	@echo "Quality Commands:"
	@echo "  make lint               - Lint the code"
	@echo "  make fix                - Fix lint issues if possible"
	@echo ""
	@echo "Utility Commands:"
	@echo "  make clean              - Clean build artifacts"
	@echo "  make size               - Show binary size"
	@echo ""
	@echo "Cross-Platform Builds:"
	@echo "  make build-macos        - Build macOS universal binary"
	@echo "  make build-linux        - Build for Linux"
	@echo "  make build-windows      - Build for Windows"
	@echo "  make build-binaries     - Build for all platforms"
	@echo ""
	@echo "Docs Commands:"
	@echo "  make docs               - Generate documentation"
	@echo "  make docs-dev           - Start dev server for docs"

build:
	cargo build

release:
	cargo build --release

test:
	cargo test

test-e2e:
	cargo test --test e2e -- --ignored

coverage:
	cargo llvm-cov --html
	@echo ""
	@echo "Coverage report generated at: target/llvm-cov/html/index.html"

lint:
	cargo fmt -- --check
	cargo clippy --all-targets --all-features -- -D warnings

fix:
	cargo fmt
	cargo clippy --all-targets --all-features --fix --allow-dirty -- -D warnings

clean:
	cargo clean

size:
	cargo build --release
	@echo "Binary size:"
	@du -h target/release/orb | awk '{print $$1}'

build-macos:
	cargo build --release --target x86_64-apple-darwin
	cargo build --release --target aarch64-apple-darwin
	lipo -create -output target/release/orb-macos-universal target/x86_64-apple-darwin/release/orb target/aarch64-apple-darwin/release/orb
	@echo "Built macOS universal binary at: target/release/orb-macos-universal"

build-linux:
	cargo build --release --target x86_64-unknown-linux-musl
	@echo "Built Linux binary at: target/x86_64-unknown-linux-musl/release/orb"

build-windows:
	cargo build --release --target x86_64-pc-windows-msvc
	@echo "Built Windows binary at: target/x86_64-pc-windows-msvc/release/orb.exe"

build-binaries: build-macos build-linux build-windows
	@echo "Built all platform binaries"

.PHONY: docs build-binaries
docs:
	cd docs && npm run build

docs-dev:
	cd docs && npm run dev
