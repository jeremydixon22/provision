"""Loopback HTTPS listener for Codex's validated workspace backend origin."""

from __future__ import annotations

import hashlib
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

from .paths import Paths

# Three calendar months can span 92 days. Renew with a wider margin so every
# freshly started daemon has at least three months of certificate validity.
_RENEW_BEFORE_SECONDS = 120 * 86400
_RENEW_CHECK_SECONDS = 3600


def _run_openssl(*args: str) -> bool:
    try:
        result = subprocess.run(["openssl", *args], capture_output=True, check=False, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _ca_valid(directory: Path) -> bool:
    ca = directory / "ca.pem"
    ca_key = directory / "ca.key"
    if not all(path.is_file() and not path.is_symlink() for path in (ca, ca_key)):
        return False
    if not _run_openssl("x509", "-checkend", str(_RENEW_BEFORE_SECONDS), "-noout", "-in", str(ca)):
        return False
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(ca, ca_key)
    except (OSError, ssl.SSLError):
        return False
    return True


def _server_certificate_valid(ca: Path, cert: Path, key: Path) -> bool:
    if not all(path.is_file() and not path.is_symlink() for path in (ca, cert, key)):
        return False
    if not _run_openssl(
        "x509", "-checkend", str(_RENEW_BEFORE_SECONDS), "-noout", "-in", str(cert)
    ):
        return False
    if not _run_openssl("verify", "-CAfile", str(ca), str(cert)):
        return False
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
    except (OSError, ssl.SSLError):
        return False
    return True


def _certificates_valid(directory: Path) -> bool:
    ca = directory / "ca.pem"
    cert = directory / "server.pem"
    key = directory / "server.key"
    return _ca_valid(directory) and _server_certificate_valid(ca, cert, key)


def _create_server_certificate(directory: Path) -> None:
    """Replace the leaf under the same CA, preserving already launched clients' trust."""
    with tempfile.TemporaryDirectory(prefix=".provision-leaf-", dir=directory) as temp:
        staging = Path(temp)
        cert = staging / "server.pem"
        key = staging / "server.key"
        csr = staging / "server.csr"
        extensions = staging / "server.ext"
        if not _run_openssl(
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(csr),
            "-subj",
            "/CN=localhost",
        ):
            raise RuntimeError("could not create the local HTTPS server key")
        extensions.write_text(
            "subjectAltName=IP:127.0.0.1,DNS:localhost\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n",
            encoding="ascii",
        )
        if not _run_openssl(
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(directory / "ca.pem"),
            "-CAkey",
            str(directory / "ca.key"),
            "-CAcreateserial",
            "-out",
            str(cert),
            "-days",
            "3650",
            "-extfile",
            str(extensions),
        ):
            raise RuntimeError("could not sign the local HTTPS server certificate")
        cert.chmod(0o600)
        key.chmod(0o600)
        if not _server_certificate_valid(directory / "ca.pem", cert, key):
            raise RuntimeError("local HTTPS certificate verification failed")
        os.replace(key, directory / "server.key")
        os.replace(cert, directory / "server.pem")


def ensure_loopback_certificate(
    paths: Paths, *, renew_server: bool = False
) -> tuple[Path, Path, Path]:
    """Keep a private CA and a currently valid certificate for 127.0.0.1."""
    directory = paths.local_tls
    if directory.is_symlink():
        raise RuntimeError("local HTTPS certificate directory must not be a symlink")
    if not _ca_valid(directory):
        paths.ensure_base()
        with tempfile.TemporaryDirectory(prefix=".provision-tls-", dir=paths.home) as temp:
            staging = Path(temp)
            ca = staging / "ca.pem"
            ca_key = staging / "ca.key"
            if not _run_openssl(
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "7300",
                "-keyout",
                str(ca_key),
                "-out",
                str(ca),
                "-subj",
                "/CN=Provision local CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ):
                raise RuntimeError("could not create the local HTTPS CA; install OpenSSL")
            for path in (ca, ca_key):
                path.chmod(0o600)
            _create_server_certificate(staging)
            if not _certificates_valid(staging):
                raise RuntimeError("local HTTPS certificate verification failed")
            if directory.exists():
                shutil.rmtree(directory)
            staging.rename(directory)
    elif renew_server or not _server_certificate_valid(
        directory / "ca.pem", directory / "server.pem", directory / "server.key"
    ):
        _create_server_certificate(directory)
    directory.chmod(0o700)
    return directory / "ca.pem", directory / "server.pem", directory / "server.key"


def codex_trust_bundle(paths: Paths, env: dict[str, str]) -> Path:
    """Trust Provision's loopback CA alongside existing public and custom roots."""
    ca = paths.local_tls / "ca.pem"
    system_ca = ssl.get_default_verify_paths().cafile
    if not system_ca:
        raise RuntimeError("system CA bundle unavailable for Codex")
    sources = [Path(system_ca)]
    custom_ca = env.get("CODEX_CA_CERTIFICATE") or env.get("SSL_CERT_FILE")
    if custom_ca:
        sources.append(Path(custom_ca).expanduser())
    sources.append(ca)
    try:
        contents = b"\n".join(source.read_bytes() for source in sources) + b"\n"
    except OSError as exc:
        raise RuntimeError("could not read a CA bundle for Codex") from exc
    digest = hashlib.sha256(contents).hexdigest()[:20]
    destination = paths.local_tls / f"codex-trust-{digest}.pem"
    if destination.is_file():
        return destination
    descriptor, temp = tempfile.mkstemp(prefix=".trust-", dir=paths.local_tls)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(contents)
        os.chmod(temp, 0o600)
        os.replace(temp, destination)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    return destination


class LoopbackTLSListener:
    """Give the existing Provision handler a second, loopback-only TLS socket."""

    def __init__(self, server: ThreadingHTTPServer, cert: Path, key: Path, paths: Paths) -> None:
        self.server = server
        self.paths = paths
        self.context = self._new_context(cert, key)
        self.certificate = cert.read_bytes()
        self.next_renewal_check = time.monotonic() + _RENEW_CHECK_SECONDS
        self.socket = socket.create_server(("127.0.0.1", 0), backlog=64)
        self.socket.settimeout(0.5)
        self.port = self.socket.getsockname()[1]
        self.stopped = threading.Event()
        self.thread = threading.Thread(
            target=self._serve, name="provision-loopback-https", daemon=True
        )
        self.thread.start()

    @staticmethod
    def _new_context(cert: Path, key: Path) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, key)
        return context

    def refresh_certificate(self) -> None:
        """Renew the leaf before expiry and use it for subsequent handshakes."""
        if not _ca_valid(self.paths.local_tls):
            raise RuntimeError("local HTTPS CA needs daemon restart for renewal")
        _ca, cert, key = ensure_loopback_certificate(self.paths)
        certificate = cert.read_bytes()
        if certificate != self.certificate:
            context = self._new_context(cert, key)
            self.context = context
            self.certificate = certificate

    def _serve(self) -> None:
        while not self.stopped.is_set():
            if time.monotonic() >= self.next_renewal_check:
                self.next_renewal_check = time.monotonic() + _RENEW_CHECK_SECONDS
                try:
                    self.refresh_certificate()
                except (OSError, RuntimeError, ssl.SSLError) as exc:
                    sys.stderr.write(f"local HTTPS certificate renewal failed: {exc}\n")
            try:
                plain, address = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                plain.settimeout(5)
                secured = self.context.wrap_socket(plain, server_side=True)
                secured.settimeout(None)
                self.server.process_request(secured, address)
            except (OSError, ssl.SSLError):
                plain.close()

    def close(self) -> None:
        self.stopped.set()
        self.socket.close()
        self.thread.join(timeout=2)
