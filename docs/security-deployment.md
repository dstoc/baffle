# Security and deployment guide

This guide describes the security boundary that Baffle provides and the
isolation that deployment must provide around it.

## HTTPS-only request model

Baffle accepts destinations through HTTP `CONNECT` only. It rejects ordinary
forward-proxy requests outside intercepted TLS, including absolute-form
`http://` and `https://` requests. It rejects plaintext `http://` destinations
on every port. Port 443 is the default. A configured TLS service on port 80 is
valid; Baffle decides from the request form and scheme, not the port number.
After successful TLS interception, Baffle processes HTTP/1.1 or HTTP/2 for
path checks and credential injection. A rule that requires interception
remains fail-closed.

Proxy clients are untrusted and may deliberately try to evade policy. Baffle
assumes that sites on the hostname allowlist behave legitimately. That site
trust does not extend to the client.

An explicit tunnel rule permits opaque traffic. Baffle cannot prove that the
bytes in that tunnel are TLS, inspect its HTTP paths, or verify the upstream
certificate. The client must verify upstream TLS identity. Baffle does not
inject credentials into tunnels, but it cannot stop a client from sending its
own credentials there. Use opaque tunnel rules only when hostname and port
authorization is sufficient without Baffle-level path or credential checks.
A fallback to an opaque tunnel on a rule that requires interception would
bypass its path checks, so Baffle closes those connections when interception
fails or the payload is unsupported. This includes malformed or fragmented
ClientHello data and TLS handshake failures. Unsupported data after CONNECT
must not turn into an opaque tunnel. The CONNECT authority, TLS SNI, and each
inner HTTP authority must remain bound on reused HTTP/1.1 and HTTP/2
connections. Baffle checks each request before it forwards the request or adds
a daemon-managed credential.

Baffle's session policy authorizes exact configured hostnames and ports. It
does not classify DNS answers or restrict destination IP addresses; deployment
DNS and egress controls own those restrictions. An allowlisted hostname may
resolve to private, loopback, link-local, metadata, or another sensitive
address, even if the service presents a valid certificate for that hostname.
A valid certificate verifies TLS identity; it does not make the destination
address safe. Apply DNS policy and default-deny network egress rules when the
threat model requires address containment. Ensure sandboxed clients cannot
bypass Baffle or reach its internal listeners.

Baffle implements HTTPS-only request admission and permits TLS on any
configured port, including port 80. It fails closed when a rule requires
interception. baffle/25 removed Baffle's DNS-answer filtering. Existing
policies that contain `private_addresses` now fail validation. Operators must
remove that field and move any required address restrictions to deployment DNS
and network egress policy before upgrading.

“HTTPS-only” describes the supported destination request model. It does not
prove that every established opaque tunnel carries TLS.

## Threat model

Baffle trusts the daemon process, the Unix UID configured as
`trusted_operator_uid`, and any process that can use the private control
socket. It treats proxy clients as untrusted, even when their configured
destinations are trusted sites. The policy assumes that allowlisted sites
behave legitimately. It does not assume that a client will send valid CONNECT
or TLS data. Session policy is trusted only after validation and must be
intersected with immutable daemon-wide secret entitlements. Baffle validates
each proxied request against the session's immutable policy and authorizes the
exact hostname and port before it dials. It does not classify, filter, or pin
resolved destination addresses. The deployment must use DNS policy and
default-deny network egress rules when its threat model requires address
containment.

Baffle can enforce exact host, port, and supported path rules for traffic that
passes through its data socket. It can tunnel authorized HTTPS without
decrypting it, or intercept HTTPS to inspect paths and add credentials. It
does not inspect tunnel contents. Path rules cannot restrict operations inside
an allowed HTTP request body, such as repository selection inside a GraphQL
body.

Baffle is not a host firewall and does not create a sandbox or network
namespace. A sandboxed process that can use another network route can bypass
its proxy policy. Baffle's internal Rama TCP listeners bind to
`127.0.0.1` in the daemon's network namespace. Any process that shares that
namespace can reach those listeners directly. Run Baffle in a network
namespace inaccessible to sandboxed clients, or enforce an equivalent
firewall boundary. Do not treat loopback or the Unix data socket alone as
network isolation.

The control protocol authenticates by UID, not by process identity. Processes
with the trusted UID are trusted. Baffle does not isolate mutually hostile
processes that share an unrestricted host account. Use a dedicated service
account and keep sandbox processes from accessing the control socket.

## Recommended deployment layout

Run the daemon as a dedicated Linux service account. Set
`trusted_operator_uid` to that account's numeric UID. The account must own the
control-socket parent, the session socket directory, and the secret directory.
It should own the CA private key so it can read the key without granting
another account access.

Create private directories before first start:

```sh
sudo install -d -o baffle -g baffle -m 0700 /var/lib/baffle
sudo install -d -o baffle -g baffle -m 0700 /var/lib/baffle/secrets
sudo install -d -o baffle -g baffle -m 0700 /run/baffle
```

Use a service manager to recreate `/run/baffle` at each boot with owner
`baffle:baffle` and mode `0700`. Point `control_socket` inside that directory
and `socket_dir` at a private subdirectory such as `/run/baffle/proxies`.
Baffle creates missing directories with mode `0700`; existing directories
must have the trusted UID as owner and must not grant group or other access.

Keep the control socket available only to the trusted orchestrator. Baffle
sets it and each per-session data socket to mode `0600`. Do not make sockets
group- or world-writable. Do not mount the control socket or the entire
session socket directory into an untrusted sandbox.

Expose only the data socket assigned to one workload. Keep the directory path
private and pass the individual socket to a trusted proxy bridge or into a
controlled mount namespace. A socket mode of `0600` allows only the owning
UID. If the workload uses a different UID, run a trusted broker under the
owner UID or configure a deliberate UID mapping; do not weaken socket
permissions to make access work. Do not give the workload access to the
control socket, CA private key, or secret directory.

The assigned data socket permits all requests in that session's policy. Treat
its path as a capability. Remove it from the workload when its lease ends.
For ephemeral sessions, the trusted client must keep the control lease open
while the workload runs and close it on normal completion, cancellation, or
failure. Persistent sessions require an explicit `stop` operation.

## CA provisioning

Create a dedicated CA for Baffle. Do not reuse a corporate, browser, or
production service CA. Keep the signing key readable only by the daemon
account. The following commands create a P-256 key and a CA certificate that
includes the required constraints:

```sh
sudo -u baffle openssl genpkey \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 \
  -out /var/lib/baffle/ca-key.pem
sudo -u baffle openssl req \
  -new -x509 \
  -key /var/lib/baffle/ca-key.pem \
  -out /var/lib/baffle/ca.pem \
  -days 365 \
  -subj "/CN=Baffle Interception CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
sudo chmod 0600 /var/lib/baffle/ca-key.pem
sudo chmod 0644 /var/lib/baffle/ca.pem
```

Choose a certificate lifetime that fits your rotation policy. The private key
must be a regular, non-symlink file. Only its owner may access it, and the
owner must have read permission. Baffle checks that the certificate is
current, has CA signing constraints, and matches the private key before
startup.

The daemon does not add its CA to any trust store. Export only the public
certificate for clients that need intercepted HTTPS:

```sh
baffle ca export \
  --config /etc/baffle/daemon.toml \
  --output /tmp/baffle-ca.pem
```

The export command creates a new file with mode `0644`; it will not replace an
existing file. Give the public certificate only to workloads whose policy
requires interception. Configure each client to trust it for the relevant
proxy connection. Do not trust it globally unless that is an explicit local
security decision. Keep the private key on the daemon host and rotate it if
the host, account, or key is compromised. Certificate-pinned clients may not
work with intercepted HTTPS.

## Secret storage

Store each credential in a separate file named by its symbolic identifier.
Set the secret directory to mode `0700` and each file to mode `0600`. The
directory and files must be owned by the trusted UID. Secret files must be
regular, non-executable files without group or other permissions. Values are
limited to 64 KiB of UTF-8 text and cannot contain control characters.

List only the required identifiers in `[secrets].allowed`. Session policies
refer to those names; they cannot supply literal secret values or file paths.
Baffle checks entitlements before opening any referenced file. It checks all
credentials before provisioning the proxy. A missing, unreadable, or
unentitled credential produces the same safe error.

Use an OS or deployment secret manager to provision the files. Avoid command
lines, environment variables, or shell history that contain credential
values. Never copy secrets into a sandbox. Baffle keeps resolved values in
the session's daemon-side state and formats them only for authorized
intercepted requests.

## Egress and client isolation

Use a network namespace that contains the daemon and its internal loopback
listeners but is not shared with sandboxed client processes. Configure the
client's network so the assigned Baffle proxy is its only permitted egress
path. A proxy URL or environment variable alone does not enforce this.

The repository includes a privileged Linux fixture that creates separate
daemon and client network namespaces, probes the daemon's internal listener,
and verifies that the listener cannot be reached from the client namespace.
Run it as described in [integration testing](integration-testing.md). Repeat
the same isolation check for the namespace, routes, mounts, and firewall used
in production. A passing fixture does not validate a different deployment
topology.

If an integration uses `socat`, run the bridge as a trusted process that can
access the assigned Unix socket. Bind its client-facing listener only where
the intended workload can reach it. Do not expose a local bridge port to
other clients unless those clients should share that session's full policy.
The [Cladding guide](cladding-integration.md) provides a working example.

Older policies may contain `private_addresses` exceptions for internal
services. Remove those entries before upgrading; the strict session schema
rejects the removed field. Apply any intended restriction through deployment
DNS policy and network egress rules. Use default-deny egress where the threat
model requires address containment. A valid certificate for an allowlisted
hostname does not make a private, loopback, link-local, metadata, or other
sensitive address safe.

## Logging, errors, and credential handling

Baffle's default log filter is `baffle_proxy=info`. Structured events include
session lifecycle, accepted or denied request metadata, and error classes.
Request logs omit URL paths, queries, headers, bodies, and resolved
credentials. Errors returned over the control protocol use safe messages and
do not include request bodies or secret values. The secret value's debug
representation is redacted.

Proxy runtime events report session lifecycle and transport error classes.
Keep logs access-controlled and review custom `RUST_LOG` filters before using
them. Do not enable request/header/body tracing in another component that
handles these connections. The deployment must protect logs as operational
metadata even though Baffle does not record credentials.

Credential injection requires an intercepted HTTPS rule and a matching host,
port, TLS identity, and path. Baffle does not inject credentials over
plaintext HTTP, into CONNECT requests, into tunnelled HTTPS, or into
unsupported upgrades. It removes a client-supplied header with the same name
before insertion. A redirect creates a new request and must match a rule
before any credential can be added.

## Safe policy design

- Allow exact hostnames, required ports, and the smallest useful path set.
- Use separate sessions for workloads that need different permissions or
  credentials.
- Prefer tunnel mode when inspection and credential injection are not needed.
- Use intercept mode only when the client trusts the dedicated Baffle CA.
- Do not treat a path allowlist as authorization for data in an allowed
  request body.
- Give upstream credentials the narrowest practical privileges.
- Review deployment DNS and network egress rules for every workload that needs
  destination-address containment.
- Recheck required interception, authority binding, and credential-isolation
  tests when updating Rama or the proxy runtime.
