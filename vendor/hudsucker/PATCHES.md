# Local Hudsucker patch

This directory contains Hudsucker 0.25.0 from crates.io. Baffle uses a local
patch because the upstream CONNECT handler can turn an unknown payload into an
opaque TCP tunnel after the handler requests interception.

The patch closes the upgraded connection when interception is selected and the
payload does not begin with a supported protocol. Tunnel mode still uses the
upstream tunnel path because its handler declines interception.

Keep this patch small. Recheck it when upgrading Hudsucker and remove the local
copy if upstream closes this fallback safely.
