# Local Hudsucker patch

This directory contains Hudsucker 0.25.0 from crates.io. Baffle uses a local
patch because the upstream CONNECT handler can turn an unknown payload into an
opaque TCP tunnel after the handler requests interception. The patch also adds
an outbound TCP connector hook and a custom DNS resolver path so callers can
validate and pin addresses for HTTP, CONNECT, and WebSocket connections.

The patch closes the upgraded connection when interception is selected and the
payload does not begin with a supported protocol. All outbound CONNECT tunnels
and WebSocket connections use the configured TCP connector. HTTP requests can
use a custom DNS resolver through the Rustls connector builder.

The upstreaming opportunity is to add these checked-connection hooks to
Hudsucker's public builder API and to make requested CONNECT interception fail
closed for unsupported payloads. The DNS resolver hook must feed the exact
addresses that the HTTP connector dials. The TCP connector hook must cover
CONNECT tunnels and WebSocket connections.

Keep this patch small. Recheck it when upgrading Hudsucker. Remove the local
copy only when upstream closes the CONNECT fallback and supports checked,
pinned outbound destinations for every connection path Baffle uses.
