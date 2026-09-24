# Baffle

Baffle is a standalone Rust daemon for creating policy-controlled HTTP and HTTPS proxies on demand. It is intended to host multiple isolated proxy sessions inside one process. Each session will have its own policy, Unix socket, and lifecycle.

The repository begins with one Rust crate. The binary is named baffle; its Cargo package is named baffle-proxy.

## Architecture

The proposal describes a Tokio daemon with a private Unix control socket and one Unix data socket per proxy session. Hudsucker handles HTTP and HTTPS proxying. A small in-process bridge connects each Unix data socket to a pre-bound loopback TCP listener used by Hudsucker.

Hudsucker is pinned to version 0.25.0 in Cargo.toml. The proposal records the security review required before Baffle can serve as a containment boundary. This initial project scaffold does not yet accept proxy traffic or enforce policies.

## Relationship to Cladding

Baffle is an independent project and has no Cladding dependency. Cladding is an intended consumer: it can submit a session policy and map the returned Unix socket into its existing proxy wiring. Baffle owns proxy sessions and policy enforcement; Cladding owns command integration and sandbox setup.

## Development

Run these checks before submitting changes:

    cargo build
    cargo test --all-features
    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings

GitHub Actions runs the formatting, Clippy, and test checks on pushes and pull requests. The workflow caches Cargo dependencies.

## Run

Start the daemon with a configuration path:

    cargo run -- daemon --config ./daemon.toml

The daemon loads and validates the TOML configuration before it starts. It still waits for Ctrl-C to exit; Unix sockets and proxy sessions will be added in later implementation work.

Read the [Baffle proposal](docs/baffle-proposal.md) for the full architecture, security requirements, and delivery plan.
