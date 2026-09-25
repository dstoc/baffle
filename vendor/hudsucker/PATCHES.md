# Local Hudsucker patch inventory

This directory contains Hudsucker 0.25.0 from crates.io. Baffle carries three
patch areas. The approved target policy treats them differently.

## Keep: strict interception and authority binding

The upstream CONNECT handler can turn an unknown payload into an opaque TCP
tunnel after the handler requests interception. The local patch adds an
explicit `Intercept`, `Tunnel`, or `Reject` result and closes the upgraded
connection when interception is required but the payload is unsupported or TLS
negotiation fails. A malformed or fragmented ClientHello must not change this
decision into an opaque tunnel. It must fail closed.

The patch passes the CONNECT authority to the TLS policy hook and intercepted
HTTP context. It checks intercepted TLS SNI against the CONNECT host and lets
the handler bind every decrypted HTTP authority to that CONNECT authority.
Plaintext HTTP after an intercepted CONNECT is rejected. These checks must
apply to each request on reused HTTP/1.1 and HTTP/2 connections. They protect
path authorization and credential injection from a malicious proxy client.

Retain these changes until an upstream Hudsucker release provides equivalent
behavior and Baffle's regression tests prove it. The test plan must include an
attempt to trigger opaque fallback by fragmenting ClientHello, unsupported
CONNECT data, malformed TLS, conflicting SNI or HTTP authority, and repeated
requests over intercepted HTTP/1.1 and HTTP/2 connections.

## Reassess: checked TCP connector hook

The local TCP connector hook covers CONNECT tunnels and WebSocket connections.
Baffle currently uses it to filter and pin destination addresses against
`private_addresses`.

baffle/25 defers destination-IP filtering to deployment DNS and network egress
controls. The checked connector may then be unnecessary. Before removing it,
verify that every CONNECT tunnel and WebSocket path authorizes the exact host
and port before dialing. Keep upstream TLS certificate and hostname
validation, and keep the network-namespace boundary. Do not retain this
connector only to enforce the deferred address filter.

## Reassess: DNS resolver hook

The resolver hook supplies the addresses used by Hudsucker's outbound HTTP
connector. Baffle currently uses it to classify DNS answers and pin an
authorized answer for the outbound connection.

After baffle/25 removes application-level address filtering, the custom
resolver hook may be unnecessary. Before removing it, verify that each HTTP
request still passes exact hostname and port authorization before dialing and
that intercepted requests still validate upstream TLS certificates and
hostnames. Deployment DNS and network egress controls own destination-address
containment when a deployment requires it.

## Upstream replacement criteria

Upstream Hudsucker 0.25.0 exposes boolean `HttpHandler` decisions and custom
HTTP and WebSocket connector hooks. Its public API does not provide the same
common checked connector for every CONNECT/TCP path or the explicit
CONNECT-bound TLS decision used by the local patch. Removing address filtering
does not by itself make the upstream crate a safe replacement.

Before replacing the vendored copy, verify the upstream API and tests against
the required CONNECT denial, strict interception, SNI/CONNECT/HTTP authority
binding, reused h1/h2 requests, and TLS verification behavior. Keep the
smallest local patch that provides any missing safeguards. Recheck this
inventory when upgrading Hudsucker.
