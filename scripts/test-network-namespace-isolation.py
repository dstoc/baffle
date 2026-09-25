#!/usr/bin/env python3
"""Run Baffle's opt-in, privileged Linux network namespace integration test."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import textwrap
import time


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check-network-namespace-isolation.py"
DAEMON_ADDRESS = "10.203.0.1"
CLIENT_ADDRESS = "10.203.0.2"


def fail(message: str) -> None:
    raise RuntimeError(message)


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        fail(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"{result.stdout}{result.stderr}"
        )
    return result


def require_commands() -> None:
    missing = [name for name in ("ip", "nsenter", "ss", "openssl") if not shutil.which(name)]
    if missing:
        fail(f"missing required commands: {', '.join(missing)}")


def namespace_command(namespace: str, *command: str) -> list[str]:
    return [
        "nsenter",
        f"--net=/run/netns/{namespace}",
        "--no-fork",
        "--",
        *command,
    ]


def start_process(
    processes: list[subprocess.Popen[str]],
    namespace: str,
    *command: str,
    stdout: int | None = subprocess.DEVNULL,
    stderr: int | None = subprocess.DEVNULL,
) -> subprocess.Popen[str]:
    child = subprocess.Popen(
        namespace_command(namespace, *command),
        stdin=subprocess.DEVNULL,
        stdout=stdout,
        stderr=stderr,
        text=True,
        bufsize=1,
    )
    processes.append(child)
    namespace_handle = os.stat(f"/run/netns/{namespace}")
    expected = (namespace_handle.st_dev, namespace_handle.st_ino)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            process_namespace = os.stat(f"/proc/{child.pid}/ns/net")
        except FileNotFoundError:
            break
        if (process_namespace.st_dev, process_namespace.st_ino) == expected:
            return child
        if child.poll() is not None:
            break
        time.sleep(0.01)
    fail(f"process {child.pid} did not enter network namespace {namespace}")


def read_startup_port(child: subprocess.Popen[str], description: str) -> int:
    if child.stdout is None:
        fail(f"{description} did not provide a startup pipe")
    deadline = time.monotonic() + 10
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if not selector.select(timeout=max(0, deadline - time.monotonic())):
                break
            line = child.stdout.readline()
            try:
                return int(line.strip())
            except ValueError:
                fail(f"{description} printed an invalid port: {line.strip()!r}")

    details = ""
    if child.poll() is not None and child.stderr is not None:
        details = child.stderr.read()
    fail(f"{description} did not start listening: {details.strip()}")


def write_test_ca(directory: Path) -> tuple[Path, Path]:
    certificate = directory / "ca.pem"
    private_key = directory / "ca-key.pem"
    run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
            "-days",
            "1",
            "-subj",
            "/CN=Baffle Namespace Test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ]
    )
    private_key.chmod(0o600)
    return certificate, private_key


def create_daemon_config(directory: Path, certificate: Path, private_key: Path) -> Path:
    control_socket = directory / "control.sock"
    socket_dir = directory / "s"
    secrets_dir = directory / "secrets"
    secrets_dir.mkdir(mode=0o700)
    config = directory / "daemon.toml"
    config.write_text(
        textwrap.dedent(
            f'''\
            [daemon]
            control_socket = "{control_socket}"
            socket_dir = "{socket_dir}"
            trusted_operator_uid = {os.getuid()}
            shutdown_grace_seconds = 1

            [ca]
            certificate = "{certificate}"
            private_key = "{private_key}"

            [secrets]
            directory = "{secrets_dir}"
            '''
        ),
        encoding="utf-8",
    )
    return config


def send_control_request(socket_path: Path, request: str) -> dict[str, object]:
    payload = request.encode("utf-8")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control:
        control.settimeout(5)
        control.connect(str(socket_path))
        control.sendall(len(payload).to_bytes(4, "big") + payload)
        length = int.from_bytes(_recv_exact(control, 4), "big")
        response = json.loads(_recv_exact(control, length))
    if response.get("ok") is not True:
        fail(f"Baffle control request failed: {response}")
    return response["result"]


def _recv_exact(connection: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = connection.recv(length - len(chunks))
        if not chunk:
            fail("Baffle closed a control connection before its response was complete")
        chunks.extend(chunk)
    return bytes(chunks)


def stop_process(child: subprocess.Popen[str]) -> None:
    if child.poll() is not None:
        return
    child.send_signal(signal.SIGTERM)
    try:
        child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=3)


def start_https_upstream(
    processes: list[subprocess.Popen[str]],
    namespace: str,
    certificate: Path,
    private_key: Path,
) -> int:
    code = textwrap.dedent(
        f"""\
        import ssl
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"baffle-unix-bridge-ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain({str(certificate)!r}, {str(private_key)!r})
        server.socket = context.wrap_socket(server.socket, server_side=True)
        print(server.server_port, flush=True)
        server.serve_forever()
        """
    )
    child = start_process(
        processes,
        namespace,
        sys.executable,
        "-u",
        "-c",
        code,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return read_startup_port(child, "HTTP upstream")


def start_route_probe(processes: list[subprocess.Popen[str]], namespace: str) -> int:
    code = textwrap.dedent(
        """\
        import socket

        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("10.203.0.1", 0))
        listener.listen()
        print(listener.getsockname()[1], flush=True)
        while True:
            connection, _ = listener.accept()
            with connection:
                connection.recv(64)
                connection.sendall(b"route-canary-ok\\n")
        """
    )
    child = start_process(
        processes,
        namespace,
        sys.executable,
        "-u",
        "-c",
        code,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return read_startup_port(child, "daemon-interface route probe")


def daemon_tcp_listeners(daemon_pid: int) -> list[tuple[str, int]]:
    spec = importlib.util.spec_from_file_location("network_namespace_checker", CHECKER)
    if spec is None or spec.loader is None:
        fail("could not load the namespace checker")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.listener_rows(daemon_pid)


def run_checker(daemon_pid: int, client_pid: int) -> subprocess.CompletedProcess[str]:
    return run(
        [sys.executable, str(CHECKER), str(daemon_pid), str(client_pid)],
        check=False,
    )


def verify_checker_negative_cases(
    processes: list[subprocess.Popen[str]], daemon_ns: str, daemon_pid: int, client_pid: int
) -> None:
    shared_ns_process = start_process(
        processes,
        daemon_ns,
        sys.executable,
        "-c",
        "import signal; signal.pause()",
    )
    same_ns = run_checker(daemon_pid, shared_ns_process.pid)
    if same_ns.returncode == 0 or "share network namespace" not in same_ns.stderr:
        fail(f"checker did not reject two processes in one namespace: {same_ns.stderr}")
    print("PASS: checker rejects daemon and client processes in the same namespace")

    wide_bind_code = textwrap.dedent(
        """\
        import signal
        import socket

        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", 0))
        listener.listen()
        print(listener.getsockname()[1], flush=True)
        signal.pause()
        """
    )
    wide_bind_process = start_process(
        processes,
        daemon_ns,
        sys.executable,
        "-u",
        "-c",
        wide_bind_code,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    wide_port = read_startup_port(wide_bind_process, "wide-bind negative fixture")
    wide_bind = run_checker(wide_bind_process.pid, client_pid)
    expected = f"0.0.0.0:{wide_port} is not bound to loopback"
    if wide_bind.returncode == 0 or expected not in wide_bind.stderr:
        fail(f"checker did not reject a non-loopback listener: {wide_bind.stderr}")
    print("PASS: checker rejects a listener bound to 0.0.0.0")


def exercise_client(
    processes: list[subprocess.Popen[str]],
    client_ns: str,
    result_path: Path,
    proxy_socket: Path,
    daemon_address: str,
    route_probe_port: int,
    internal_port: int,
    upstream_port: int,
) -> subprocess.Popen[str]:
    code = textwrap.dedent(
        f'''\
        import errno
        import ssl
        import signal
        import socket
        import sys
        import traceback
        from pathlib import Path

        result_path = Path({str(result_path)!r})
        try:
            # This reachable listener proves the veth route reaches the daemon namespace.
            with socket.create_connection(({daemon_address!r}, {route_probe_port}), timeout=3) as probe:
                probe.sendall(b"route-check")
                route_result = probe.recv(64)
                assert route_result == b"route-canary-ok\\n", route_result

            # Probe the daemon's veth address at the actual internal listener port.
            # The request never targets this client's own 127.0.0.1 or ::1.
            try:
                with socket.create_connection(({daemon_address!r}, {internal_port}), timeout=2):
                    raise AssertionError("sandbox client reached Baffle's internal TCP port")
            except OSError as error:
                assert error.errno == errno.ECONNREFUSED, (
                    "the daemon interface route should be reachable and the loopback-only "
                    f"listener should refuse this address; got {{error!r}}"
                )

            # The same client can use the assigned Unix data socket and reach its allowed HTTPS upstream.
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as proxy:
                proxy.settimeout(5)
                proxy.connect({str(proxy_socket)!r})
                connect_request = (
                    f"CONNECT localhost:{upstream_port} HTTP/1.1\\r\\n"
                    f"Host: localhost:{upstream_port}\\r\\n"
                    "\\r\\n"
                )
                proxy.sendall(connect_request.encode())
                connect_response = bytearray()
                while b"\\r\\n\\r\\n" not in connect_response:
                    chunk = proxy.recv(4096)
                    if not chunk:
                        raise AssertionError("proxy closed before sending CONNECT headers")
                    connect_response.extend(chunk)
                connect_headers = bytes(connect_response).split(b"\\r\\n\\r\\n", 1)[0]
                assert b" 200 " in connect_headers.split(b"\\r\\n", 1)[0], connect_headers

                tls_context = ssl.create_default_context()
                tls_context.check_hostname = False
                tls_context.verify_mode = ssl.CERT_NONE
                with tls_context.wrap_socket(proxy, server_hostname="localhost") as upstream:
                    request = (
                        f"GET /namespace-check HTTP/1.1\\r\\n"
                        f"Host: localhost:{upstream_port}\\r\\n"
                        "Connection: close\\r\\n\\r\\n"
                    )
                    upstream.sendall(request.encode())
                    response = bytearray()
                    while b"\\r\\n\\r\\n" not in response:
                        chunk = upstream.recv(4096)
                        if not chunk:
                            raise AssertionError("proxy closed before sending HTTPS headers")
                        response.extend(chunk)
                    headers, body = bytes(response).split(b"\\r\\n\\r\\n", 1)
                    content_length = next(
                        int(line.split(b":", 1)[1])
                        for line in headers.split(b"\\r\\n")[1:]
                        if line.lower().startswith(b"content-length:")
                    )
                    while len(body) < content_length:
                        chunk = upstream.recv(4096)
                        if not chunk:
                            raise AssertionError("proxy closed before sending the full HTTPS body")
                        body += chunk
            assert b"HTTP/1.1 200" in headers or b"HTTP/1.0 200" in headers, headers[:500]
            assert b"baffle-unix-bridge-ok" in body, body[-500:]
            result_path.write_text("PASS: routed probe refused; Unix socket proxy returned HTTPS 200 through CONNECT\\n")
            signal.pause()
        except BaseException:
            result_path.write_text("FAIL\\n" + traceback.format_exc())
            raise
        '''
    )
    compile(code, "<sandbox-client>", "exec")
    return start_process(
        processes,
        client_ns,
        sys.executable,
        "-u",
        "-c",
        code,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )


def wait_for_client_result(
    child: subprocess.Popen[str], result_path: Path, timeout_seconds: float = 15
) -> str:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if result_path.exists():
            result = result_path.read_text(encoding="utf-8")
            if result.startswith("FAIL"):
                fail(result)
            return result.strip()
        if child.poll() is not None:
            error = child.stderr.read() if child.stderr is not None else ""
            fail(f"sandbox client exited before completing the probes: {error.strip()}")
        time.sleep(0.05)
    fail("sandbox client timed out before completing the probes")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary",
        type=Path,
        default=ROOT / "target" / "debug" / "baffle",
        help="path to a built Baffle daemon binary (default: target/debug/baffle)",
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        fail("run this opt-in test as root, for example: sudo python3 scripts/test-network-namespace-isolation.py")
    require_commands()
    binary = args.binary.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        fail(f"Baffle binary is missing or not executable: {binary}; build it with cargo build --bin baffle")

    suffix = secrets.token_hex(3)
    daemon_ns = f"bf-d-{suffix}"
    client_ns = f"bf-c-{suffix}"
    daemon_link = f"bd{suffix}"
    client_link = f"bc{suffix}"
    processes: list[subprocess.Popen[str]] = []
    namespace_names: list[str] = []
    temporary_directory = Path(tempfile.mkdtemp(prefix="bfi-"))
    try:
        run(["ip", "netns", "add", daemon_ns])
        namespace_names.append(daemon_ns)
        run(["ip", "netns", "add", client_ns])
        namespace_names.append(client_ns)
        run(["ip", "link", "add", daemon_link, "type", "veth", "peer", "name", client_link])
        run(["ip", "link", "set", daemon_link, "netns", daemon_ns])
        run(["ip", "link", "set", client_link, "netns", client_ns])
        for namespace in (daemon_ns, client_ns):
            run(["ip", "-n", namespace, "link", "set", "lo", "up"])
        run(["ip", "-n", daemon_ns, "address", "add", f"{DAEMON_ADDRESS}/30", "dev", daemon_link])
        run(["ip", "-n", client_ns, "address", "add", f"{CLIENT_ADDRESS}/30", "dev", client_link])
        run(["ip", "-n", daemon_ns, "link", "set", daemon_link, "up"])
        run(["ip", "-n", client_ns, "link", "set", client_link, "up"])
        print(f"Created daemon/client namespaces {daemon_ns} and {client_ns} with a veth link")

        certificate, private_key = write_test_ca(temporary_directory)
        config = create_daemon_config(temporary_directory, certificate, private_key)
        daemon = start_process(
            processes,
            daemon_ns,
            str(binary),
            "daemon",
            "--config",
            str(config),
            stderr=subprocess.PIPE,
        )
        control_socket = temporary_directory / "control.sock"
        deadline = time.monotonic() + 15
        while not control_socket.exists() and time.monotonic() < deadline:
            if daemon.poll() is not None:
                details = daemon.stderr.read() if daemon.stderr is not None else ""
                fail(f"Baffle exited before starting: {details.strip()}")
            time.sleep(0.05)
        if not control_socket.exists():
            fail("Baffle did not create its control socket")

        upstream_port = start_https_upstream(
            processes, daemon_ns, certificate, private_key
        )
        route_probe_port = start_route_probe(processes, daemon_ns)
        request = textwrap.dedent(
            f'''\
            version = 1
            operation = "create"

            [session]
            persistent = true

            [[rules]]
            host = "localhost"
            mode = "tunnel"
            ports = [{upstream_port}]
            '''
        )
        created = send_control_request(control_socket, request)
        proxy_socket = Path(str(created["socket"]))
        if not proxy_socket.exists():
            fail(f"Baffle reported a missing session socket: {proxy_socket}")
        daemon_pid = daemon.pid

        listeners = daemon_tcp_listeners(daemon_pid)
        loopback_ports = [
            port for address, port in listeners if address in {"127.0.0.1", "::1"}
        ]
        if not loopback_ports:
            fail(f"Baffle has no loopback internal TCP listener: {listeners}")
        internal_port = loopback_ports[0]

        client_result = temporary_directory / "client-result"
        client = exercise_client(
            processes,
            client_ns,
            client_result,
            proxy_socket,
            DAEMON_ADDRESS,
            route_probe_port,
            internal_port,
            upstream_port,
        )
        print(wait_for_client_result(client, client_result))

        checker = run_checker(daemon_pid, client.pid)
        if checker.returncode != 0:
            fail(f"namespace checker failed:\n{checker.stdout}{checker.stderr}")
        print(checker.stdout.strip())
        print(
            "PASS: the client reached the daemon veth canary, was refused at the daemon's "
            f"internal port {internal_port}, and received its upstream response through the Unix socket"
        )

        verify_checker_negative_cases(processes, daemon_ns, daemon_pid, client.pid)
    finally:
        for child in reversed(processes):
            stop_process(child)
        run(["ip", "link", "del", daemon_link], check=False)
        for namespace in reversed(namespace_names):
            run(["ip", "netns", "del", namespace], check=False)
        shutil.rmtree(temporary_directory, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        message = str(error)[:3000]
        annotation = (
            message.replace("%", "%25")
            .replace("\r", "%0D")
            .replace("\n", "%0A")
        )
        print(
            f"::error title=Privileged namespace integration failure::{annotation}",
            flush=True,
        )
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
