# Local Hudsucker patch inventory

This directory contains Hudsucker 0.25.0 from crates.io. baffle/25 removed
Baffle's custom TCP connector and DNS resolver hooks. The remaining local patch
preserves fail-closed interception and authority binding.

## Retain: fail-closed CONNECT interception

Upstream Hudsucker 0.25.0 can open a raw TCP tunnel when CONNECT interception
was requested but the received payload does not match its recognized TLS or
WebSocket forms. The local patch reads the initial payload prefix, asks the
handler for an explicit `Intercept`, `Tunnel`, or `Reject` TLS decision, and
closes unsupported payloads when policy requires interception. Malformed or
fragmented ClientHello data must not select an opaque tunnel. A failed TLS
handshake also closes the connection.

The patch passes the CONNECT authority to the TLS policy hook and records it in
the intercepted HTTP context. It checks TLS SNI against the CONNECT host and
lets Baffle bind every decrypted HTTP authority to the CONNECT authority.
Plaintext HTTP after an intercepted CONNECT is rejected. These checks apply to
each request on reused HTTP/1.1 and HTTP/2 connections. They protect path
authorization and credential injection from an untrusted client.

Baffle's regression tests cover unsupported CONNECT data, malformed TLS,
conflicting SNI and HTTP authority, request checks on reused connections,
credential isolation, and normal upstream certificate validation. The
fragmented ClientHello regression is tracked separately in baffle/24. Keep the
local patch until an upstream release provides the same behavior and Baffle's
tests verify it.

## Benchmark-only TCP_NODELAY control

The local `benchmark-tcp-nodelay` feature supports baffle/32 measurements. It
can set `TCP_NODELAY` on accepted proxy sockets and on Hudsucker's outbound HTTP
connector when `BAFFLE_BENCH_TCP_NODELAY` selects `proxy-ingress`,
`proxy-egress`, or `all`. The feature is opt-in. Normal builds keep Hudsucker's
upstream socket defaults.

## Removed: address-filtering connector and resolver

The prior local TCP connector covered CONNECT and WebSocket connections. The
paired resolver supplied DNS answers to Hudsucker's outbound HTTP connector.
Baffle used them to classify addresses, filter DNS answers, and pin an
approved answer to each outbound connection.

baffle/25 removed both hooks and `src/egress.rs`. The runtime uses upstream
Hudsucker's default Rustls HTTP connector, CONNECT TCP dialer, and WebSocket
connector. Baffle authorizes the exact hostname and port before the request
reaches those outbound paths. The Rustls client keeps normal upstream
certificate-chain and hostname validation. A local integration test confirms
that an authorized loopback destination is dialed and that an untrusted
upstream certificate is rejected.

Destination-address restrictions now belong to deployment DNS policy and
network egress controls. The network-namespace boundary that prevents clients
from reaching Baffle's internal listeners remains required.

## Exact upstream gaps

The public Hudsucker 0.25.0 `HttpHandler` API has boolean CONNECT and TLS
decisions. It does not provide Baffle's explicit reject decision for failed
interception. Its TLS hook does not receive the CONNECT authority, and its
intercepted HTTP context does not retain that authority for per-request
binding. Its CONNECT handling can send unsupported payloads into an opaque
tunnel. Those gaps prevent replacing the vendored source safely.

The upstream builder does provide `with_rustls_connector`, custom HTTP and
WebSocket connector options, and its default outbound connection paths.
Address filtering does not require a Baffle-specific connector. Review the
[Hudsucker 0.25.0 handler API](https://docs.rs/hudsucker/0.25.0/hudsucker/trait.HttpHandler.html)
and [builder API](https://docs.rs/hudsucker/0.25.0/hudsucker/builder/struct.ProxyBuilder.html)
when reassessing the pin. Do not remove the remaining local patch until an
upstream API and tests preserve fail-closed interception, CONNECT/TLS/HTTP
authority binding, reused HTTP/1.1 and HTTP/2 checks, and normal TLS
verification.
