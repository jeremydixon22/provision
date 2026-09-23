from __future__ import annotations

import ssl
import stat
import subprocess
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from provision.daemon import ProvisionServer
from provision.local_tls import (
    LoopbackTLSListener,
    codex_trust_bundle,
    ensure_loopback_certificate,
)
from provision.paths import Paths


class LoopbackTLSTests(unittest.TestCase):
    def test_codex_can_trust_private_https_listener_without_changing_system_trust(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = Paths(Path(temp) / "home")
            paths.ensure_base()
            ca, cert, key = ensure_loopback_certificate(paths)
            self.assertEqual((ca, cert, key), ensure_loopback_certificate(paths))
            self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((paths.local_tls / "ca.key").stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(paths.local_tls.stat().st_mode), 0o700)
            for certificate in (ca, cert):
                check = subprocess.run(
                    [
                        "openssl",
                        "x509",
                        "-checkend",
                        str(93 * 86400),
                        "-noout",
                        "-in",
                        str(certificate),
                    ],
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(check.returncode, 0, check.stderr.decode(errors="replace"))
            bundle = codex_trust_bundle(paths, {})
            self.assertEqual(stat.S_IMODE(bundle.stat().st_mode), 0o600)

            server = ProvisionServer(("127.0.0.1", 0), paths)
            try:
                server.local_tls_listener = LoopbackTLSListener(server, cert, key, paths)
                url = f"https://127.0.0.1:{server.local_tls_listener.port}/health"
                with urllib.request.urlopen(
                    url, context=ssl.create_default_context(cafile=str(bundle)), timeout=3
                ) as response:
                    self.assertEqual(response.status, 200)
                    self.assertIn(b'"local_tls_port":', response.read())
                with self.assertRaises(urllib.error.URLError) as error:
                    urllib.request.urlopen(url, timeout=3)
                self.assertIsInstance(error.exception.reason, ssl.SSLCertVerificationError)
            finally:
                server.server_close()

    def test_renewed_server_certificate_keeps_existing_codex_trust(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = Paths(Path(temp) / "home")
            ca, cert, key = ensure_loopback_certificate(paths)
            original_ca = ca.read_bytes()
            original_cert = cert.read_bytes()
            bundle = codex_trust_bundle(paths, {})
            original_bundle = bundle.read_bytes()
            server = ProvisionServer(("127.0.0.1", 0), paths)
            try:
                listener = LoopbackTLSListener(server, cert, key, paths)
                server.local_tls_listener = listener
                ensure_loopback_certificate(paths, renew_server=True)
                listener.refresh_certificate()
                self.assertEqual(ca.read_bytes(), original_ca)
                self.assertNotEqual(cert.read_bytes(), original_cert)
                self.assertEqual(bundle.read_bytes(), original_bundle)
                url = f"https://127.0.0.1:{listener.port}/health"
                with urllib.request.urlopen(
                    url, context=ssl.create_default_context(cafile=str(bundle)), timeout=3
                ) as response:
                    self.assertEqual(response.status, 200)
            finally:
                server.server_close()

    def test_startup_renews_a_certificate_with_less_than_three_months_left(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = Paths(Path(temp) / "home")
            ca, cert, key = ensure_loopback_certificate(paths)
            original_ca = ca.read_bytes()
            csr = Path(temp) / "short.csr"
            extensions = Path(temp) / "short.ext"
            extensions.write_text(
                "subjectAltName=IP:127.0.0.1,DNS:localhost\n"
                "basicConstraints=critical,CA:FALSE\n"
                "extendedKeyUsage=serverAuth\n",
                encoding="ascii",
            )
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-new",
                    "-key",
                    str(key),
                    "-out",
                    str(csr),
                    "-subj",
                    "/CN=localhost",
                ],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "openssl",
                    "x509",
                    "-req",
                    "-in",
                    str(csr),
                    "-CA",
                    str(ca),
                    "-CAkey",
                    str(paths.local_tls / "ca.key"),
                    "-out",
                    str(cert),
                    "-days",
                    "90",
                    "-extfile",
                    str(extensions),
                ],
                check=True,
                capture_output=True,
            )
            short_cert = cert.read_bytes()
            ensure_loopback_certificate(paths)
            self.assertEqual(ca.read_bytes(), original_ca)
            self.assertNotEqual(cert.read_bytes(), short_cert)
            self.assertEqual(
                subprocess.run(
                    ["openssl", "x509", "-checkend", str(93 * 86400), "-noout", "-in", str(cert)],
                    check=False,
                    capture_output=True,
                ).returncode,
                0,
            )

    def test_startup_replaces_a_ca_with_less_than_three_months_left(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = Paths(Path(temp) / "home")
            ca, cert, _key = ensure_loopback_certificate(paths)
            ca_key = paths.local_tls / "ca.key"
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-key",
                    str(ca_key),
                    "-days",
                    "90",
                    "-out",
                    str(ca),
                    "-subj",
                    "/CN=Provision local CA",
                    "-addext",
                    "basicConstraints=critical,CA:TRUE",
                    "-addext",
                    "keyUsage=critical,keyCertSign,cRLSign",
                ],
                check=True,
                capture_output=True,
            )
            short_ca = ca.read_bytes()
            ensure_loopback_certificate(paths)
            self.assertNotEqual(ca.read_bytes(), short_ca)
            for certificate in (ca, cert):
                self.assertEqual(
                    subprocess.run(
                        [
                            "openssl",
                            "x509",
                            "-checkend",
                            str(93 * 86400),
                            "-noout",
                            "-in",
                            str(certificate),
                        ],
                        check=False,
                        capture_output=True,
                    ).returncode,
                    0,
                )

    def test_missing_custom_ca_bundle_fails_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = Paths(Path(temp) / "home")
            ensure_loopback_certificate(paths)
            with self.assertRaisesRegex(RuntimeError, "could not read a CA bundle"):
                codex_trust_bundle(paths, {"CODEX_CA_CERTIFICATE": str(Path(temp) / "missing.pem")})
