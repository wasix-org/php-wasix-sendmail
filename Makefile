all: build install

build:
	cargo +wasix build -r --target wasm32-wasmer-wasi

# Assuming we live right next to the wasix-org/php-wasix-deps repo
install:
	cp target/wasm32-wasmer-wasi/release/libwasix_sendmail.a ../php-wasix-deps/lib/
