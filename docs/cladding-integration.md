# Cladding and other consumers

Baffle is an independent daemon. It has no Cladding dependency and this
repository makes no Cladding changes. A trusted consumer creates a session
over the Unix control socket, gives its workload access to the returned data
socket, and owns the session lease for the workload's lifetime.

## Consumer integration steps

1. Run Baffle as a dedicated Linux service account and make the control socket
   available only to the trusted orchestrator.
2. Create a policy for one workload. Use the `baffle-client` crate from Rust,
   or implement the [control protocol](control-protocol.md) in another
   language.
3. Keep the returned `Session` handle alive while an ephemeral workload runs.
   Its control connection is the lease. Close or drop the handle after normal
   completion, cancellation, or failure.
4. Expose only that session's data socket to the assigned workload. Use a
   trusted bridge or controlled mount and preserve mode `0600`; do not expose
   the control socket or the full socket directory.
5. Ensure the sandbox cannot reach Baffle's internal loopback TCP listeners
   and cannot bypass the proxy for external network access. See the
   [security and deployment guide](security-deployment.md).

For a persistent session, close the create connection after the response and
send an explicit `stop` operation during cleanup. Use `list` to inspect
sessions owned by the same trusted UID.

## Rust client example

`examples/client.rs` opens an HTTPS CONNECT tunnel to the configured host and
port. It does not send a TLS request or verify a server certificate. The
`cladding_socat` example below connects a full HTTPS client through CONNECT.

`examples/client.rs` creates an ephemeral policy, sends CONNECT to
`example.com:443` through the session's Unix data socket, prints the tunnel
status, and closes the lease. Set `BAFFLE_EXAMPLE_HOST` and
`BAFFLE_EXAMPLE_PORT` to select another host and TLS port. Port 80 is rejected.

Start Baffle with a valid daemon configuration, then run:

```sh
BAFFLE_CONTROL_SOCKET=/run/baffle/control.sock cargo run --locked --example client
```

The example defaults to `/run/baffle/control.sock`, host `example.com`, and
port 443. Set `BAFFLE_CONTROL_SOCKET` to use another control path. It needs a
reachable upstream that accepts a TCP connection on the selected port. The
example verifies only that CONNECT is established; it does not perform
client-side TLS verification. CI compiles this example and parses the TOML
files in `examples/`; it does not start a daemon or a live upstream server.

## Cladding `socat` example

The standalone [`examples/cladding_socat.rs`](../examples/cladding_socat.rs)
creates an HTTPS tunnel session and starts `socat` as a TCP-to-Unix bridge.
Run it as the trusted UID that Baffle expects on the control socket:

```sh
BAFFLE_CONTROL_SOCKET=/run/baffle/control.sock \
BAFFLE_BRIDGE_PORT=18080 \
cargo run --locked --example cladding_socat -- github.com
```

The final argument is the one exact hostname allowed by the session. Configure
the existing Cladding proxy setting to use
`http://127.0.0.1:18080`. To check it manually, run this in another terminal
that can reach the bridge:

```sh
curl --proxy http://127.0.0.1:18080 https://github.com/
```

Press Ctrl-C to stop `socat` and close the ephemeral session. The example
requires `socat` on `PATH`, a running Baffle daemon, and access to the Baffle
source checkout. The TCP listener is bound to loopback in the namespace where
the example runs. Keep that namespace isolated from untrusted clients and keep
Baffle's own loopback listeners in a separate, inaccessible network
namespace.

The example illustrates the consumer boundary. A production Cladding
integration should create one Baffle session per independently configured
workload, hold each lease for the workload's full lifetime, and expose only
the assigned data socket or its local bridge. Cladding should retain
responsibility for sandbox setup, proxy environment variables, cancellation,
and ensuring the workload has no alternate egress path.

## Non-Rust consumers

Consumers that do not use Rust can send the same length-prefixed UTF-8 TOML
and JSON frames as `baffle-client`. They must authenticate as the configured
trusted UID and retain the create connection for ephemeral sessions. See
[control protocol](control-protocol.md) for framing, request examples, errors,
and lease cleanup.
