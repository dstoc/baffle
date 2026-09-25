# Cladding integration example

Cladding can use Baffle without adding a Cladding dependency to this repository. The example creates one ephemeral session, then runs `socat` as Cladding's local TCP-to-Unix-socket bridge.

Start the Baffle daemon with a control socket that the Cladding task can access. Then run this example in the Cladding network and mount namespace:

```sh
BAFFLE_CONTROL_SOCKET=/run/baffle/control.sock \
BAFFLE_BRIDGE_PORT=18080 \
cargo run --example cladding_socat -- github.com
```

The final argument is the exact hostname allowed by the session. The example prints the local proxy URL. Configure Cladding's existing HTTP proxy setting to use `http://127.0.0.1:18080`. For a standalone check, run `curl --proxy http://127.0.0.1:18080 https://github.com/` in another terminal. Press Ctrl-C to stop `socat` and release the ephemeral session.

The bridge uses `TCP-LISTEN` bound to loopback in Cladding's network namespace and `UNIX-CONNECT` to reach the session socket. Keep Baffle's own loopback TCP listeners in a network namespace that Cladding cannot access. The Unix control socket must remain available only to the trusted operator, and the session socket must be mounted only into its assigned task.

This example needs `socat` on `PATH`, a running Baffle daemon, and the Baffle source checkout. It does not import or link Cladding code.
