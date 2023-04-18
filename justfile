debug_path := "target/debug/doit"
release_path := "target/release/doit"

env_prep:
    rustup default stable

debug: env_prep
    cargo build
    chmod 4755 {{debug_path}}

release: env_prep
    cargo build --release
    chmod 4755 {{release_path}}

clean:
    cargo clean
