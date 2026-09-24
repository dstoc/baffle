# Baffle

Baffle is a standalone Rust daemon for creating policy-controlled HTTP and HTTPS proxies on demand. It hosts multiple isolated proxy sessions inside one process. Each session has its own policy, Unix socket, and lifecycle.

The repository contains one Rust crate. The binary is named baffle; its Cargo package is named baffle-proxy.

## Architecture

The proposal describes a Tokio daemon with a private Unix control socket and one Unix data socket per proxy session. Hudsucker handles HTTP and HTTPS proxying. A small in-process bridge connects each Unix data socket to a pre-bound loopback TCP listener used by Hudsucker.

Hudsucker is pinned to version 0.25.0 in Cargo.toml. Each session has a distinct Unix data socket and a streaming bridge to its private loopback TCP listener. The current handler denies outbound requests while policy enforcement is under development.

## Deployment security requirement

Run Baffle in a network namespace that sandboxed proxy clients cannot access. The session TCP ports bind to loopback inside Baffle's namespace, but loopback does not isolate processes that share that namespace. Expose only the control socket to the trusted operator and each session's Unix data socket to its assigned client. Do not treat the per-session socket as a security boundary if clients can connect to Baffle's internal TCP ports directly.

## Relationship to Cladding

Baffle is an independent project and has no Cladding dependency. Cladding is an intended consumer: it can submit a session policy and map the returned Unix socket into its existing proxy wiring. Baffle owns proxy sessions and policy enforcement; Cladding owns command integration and sandbox setup.

## Development

Run these checks before submitting changes:

    cargo build
    cargo test --all-features
    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings

GitHub Actions runs the formatting, Clippy, and test checks on pushes and pull requests. The workflow caches Cargo dependencies.

## Certificate authority

The daemon loads the CA certificate and private key from the paths in `[ca]`. The certificate must be current and marked for certificate signing. The private key must match the certificate, be a regular file, and allow read access only to its owner. Use mode `0400` or `0600` for the key file.

Export the public certificate for clients that need to trust intercepted HTTPS:

    cargo run -- ca export --config ./daemon.toml --output ./baffle-ca.pem

The command writes a new public certificate file with mode `0644`. It fails if the output path already exists. It does not read or export the private key.

## Run

Start the daemon with a configuration path:

    cargo run -- daemon --config ./daemon.toml

The daemon loads and validates the TOML configuration before it starts. It binds the private Unix control socket and serves the versioned control protocol until it receives Ctrl-C.

Session creation starts a deny-all Hudsucker instance on a pre-bound, per-session loopback TCP listener and returns a randomly named, per-session Unix data socket. The in-process bridge streams data between the two listeners and applies the configured per-session connection limit. Runtime failures are isolated to that session.

Read the [control protocol](docs/control-protocol.md) for the wire format and the [Baffle proposal](docs/baffle-proposal.md) for the full architecture, security requirements, and delivery plan.
