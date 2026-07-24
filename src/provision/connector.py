"""Generic, local-first Connector ABI primitives.

The Connector ABI is a small daemon-to-connector boundary for carrying named,
bounded frames.  A connector may route frames locally, directly to another
host, or through a relay.  Provision intentionally supplies none of those
transports and does not treat a connector as an encryption implementation.

The connector is a trusted local process: it authenticates to a mode-0600 Unix
socket with a distinct capability.  Any network peer identity, cryptography,
pairing, and relay policy stay above this ABI.  This keeps the local daemon,
terminal workflow, dashboard, and OpenAI proxy out of the connector path.
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
import hmac
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import threading
from typing import Any


CONNECTOR_ABI_VERSION = 1
CONNECTOR_MAX_MESSAGE_BYTES = 384 * 1024
CONNECTOR_MAX_FRAME_BYTES = 256 * 1024
CONNECTOR_MAX_LANES = 16
CONNECTOR_LINK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
CONNECTOR_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$")
CONNECTOR_LANE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}(?:\.[a-z0-9_-]{1,32})*/v[1-9][0-9]*$")


class ConnectorError(RuntimeError):
    """A Connector ABI message or local connector lifecycle operation failed."""


def compact_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def connector_abi_payload() -> dict[str, Any]:
    """Return the stable discovery document for Connector ABI v1."""
    return {
        "abi": CONNECTOR_ABI_VERSION,
        "framing": "jsonl",
        "frame_encoding": "base64url",
        "max_message_bytes": CONNECTOR_MAX_MESSAGE_BYTES,
        "max_frame_bytes": CONNECTOR_MAX_FRAME_BYTES,
        "message_types": ["hello", "hello_ack", "frame", "frame_ack", "error"],
    }


def _validate_identifier(value: Any, pattern: re.Pattern[str], label: str) -> str:
    text = str(value or "")
    if not pattern.fullmatch(text):
        raise ConnectorError(f"invalid connector {label}")
    return text


def validate_connector_lanes(value: Any) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > CONNECTOR_MAX_LANES:
        raise ConnectorError("invalid connector lanes")
    lanes = sorted({str(item) for item in value})
    if not lanes or any(not CONNECTOR_LANE_RE.fullmatch(lane) for lane in lanes):
        raise ConnectorError("invalid connector lane")
    return lanes


def encode_connector_message(value: Mapping[str, Any]) -> bytes:
    encoded = compact_json_bytes(dict(value))
    if len(encoded) > CONNECTOR_MAX_MESSAGE_BYTES:
        raise ConnectorError("connector message exceeds its byte limit")
    return encoded + b"\n"


def decode_connector_message(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > CONNECTOR_MAX_MESSAGE_BYTES:
        raise ConnectorError("invalid connector message")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConnectorError("invalid connector message") from exc
    if not isinstance(value, dict):
        raise ConnectorError("invalid connector message")
    if value.get("abi") != CONNECTOR_ABI_VERSION:
        raise ConnectorError("unsupported connector ABI")
    if not isinstance(value.get("type"), str):
        raise ConnectorError("invalid connector message")
    return value


def connector_frame(
    *,
    link_id: str,
    lane: str,
    payload: bytes,
    message_id: str = "",
) -> dict[str, Any]:
    """Build a bounded opaque frame for a named connector lane."""
    link = _validate_identifier(link_id, CONNECTOR_LINK_ID_RE, "link ID")
    lane_name = _validate_identifier(lane, CONNECTOR_LANE_RE, "lane")
    if not isinstance(payload, bytes) or len(payload) > CONNECTOR_MAX_FRAME_BYTES:
        raise ConnectorError("connector frame exceeds its byte limit")
    result: dict[str, Any] = {
        "type": "frame",
        "abi": CONNECTOR_ABI_VERSION,
        "link_id": link,
        "lane": lane_name,
        "payload": base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii"),
    }
    if message_id:
        result["message_id"] = _validate_identifier(message_id, CONNECTOR_LINK_ID_RE, "message ID")
    return result


def decode_connector_frame(value: Mapping[str, Any]) -> tuple[str, str, bytes, str]:
    if value.get("type") != "frame":
        raise ConnectorError("invalid connector frame")
    link_id = _validate_identifier(value.get("link_id"), CONNECTOR_LINK_ID_RE, "link ID")
    lane = _validate_identifier(value.get("lane"), CONNECTOR_LANE_RE, "lane")
    message_id = str(value.get("message_id") or "")
    if message_id:
        _validate_identifier(message_id, CONNECTOR_LINK_ID_RE, "message ID")
    encoded = value.get("payload")
    if not isinstance(encoded, str) or len(encoded) > CONNECTOR_MAX_FRAME_BYTES * 2:
        raise ConnectorError("invalid connector frame")
    try:
        payload = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, UnicodeEncodeError) as exc:
        raise ConnectorError("invalid connector frame") from exc
    if len(payload) > CONNECTOR_MAX_FRAME_BYTES:
        raise ConnectorError("connector frame exceeds its byte limit")
    return link_id, lane, payload, message_id


ConnectorFrameHandler = Callable[[str, str, str, bytes], bytes | None]


class LocalConnectorHub:
    """A same-user Unix-socket endpoint for a trusted connector process.

    The hub carries opaque bytes to a registered lane handler.  It has no
    network listener, relay logic, routing policy, or cryptography.  A process
    that holds its capability is intentionally part of the local trust boundary.
    """

    def __init__(
        self,
        path: Path,
        token: str,
        lane_handlers: Mapping[str, ConnectorFrameHandler],
    ) -> None:
        self.path = path
        self.token = token
        self.lane_handlers = dict(lane_handlers)
        self.listener: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.lock = threading.RLock()

    def start(self) -> None:
        if not hasattr(socket, "AF_UNIX"):
            raise ConnectorError("local connector sockets are unsupported on this platform")
        with self.lock:
            if self.thread and self.thread.is_alive():
                return
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists() or self.path.is_symlink():
                details = self.path.lstat()
                if not stat.S_ISSOCK(details.st_mode):
                    raise ConnectorError("connector socket path is not a socket")
                self.path.unlink()
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                listener.bind(str(self.path))
                self.path.chmod(0o600)
                listener.listen(8)
                listener.settimeout(0.5)
            except BaseException:
                listener.close()
                raise
            self.listener = listener
            self.stop_event.clear()
            self.thread = threading.Thread(
                target=self._serve,
                name="provision-connector-hub",
                daemon=True,
            )
            self.thread.start()

    def stop(self) -> None:
        with self.lock:
            self.stop_event.set()
            listener = self.listener
            thread = self.thread
            self.listener = None
            self.thread = None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        if thread and thread is not threading.current_thread():
            thread.join(timeout=2)
        try:
            details = self.path.lstat()
        except FileNotFoundError:
            return
        except OSError:
            return
        # Do not remove an unrelated entry if another local process replaced
        # the endpoint while the hub was stopping.
        if stat.S_ISSOCK(details.st_mode):
            try:
                self.path.unlink()
            except OSError:
                pass

    def running(self) -> bool:
        with self.lock:
            return bool(self.thread and self.thread.is_alive() and self.listener is not None)

    def _serve(self) -> None:
        while not self.stop_event.is_set():
            listener = self.listener
            if listener is None:
                return
            try:
                connection, _address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            thread = threading.Thread(target=self._handle_connection, args=(connection,), daemon=True)
            thread.start()

    @staticmethod
    def _peer_is_current_user(connection: socket.socket) -> bool:
        if not hasattr(socket, "SO_PEERCRED"):
            return False
        try:
            raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            _pid, uid, _gid = struct.unpack("3i", raw)
        except OSError:
            return False
        return uid == os.geteuid()

    @staticmethod
    def _receive_message(connection: socket.socket, buffered: bytearray) -> dict[str, Any]:
        connection.settimeout(5)
        while b"\n" not in buffered:
            if len(buffered) >= CONNECTOR_MAX_MESSAGE_BYTES:
                raise ConnectorError("connector message exceeds its byte limit")
            chunk = connection.recv(min(4096, CONNECTOR_MAX_MESSAGE_BYTES + 1 - len(buffered)))
            if not chunk:
                raise ConnectorError("connector connection closed")
            buffered.extend(chunk)
        line, _, remainder = buffered.partition(b"\n")
        buffered[:] = remainder
        return decode_connector_message(bytes(line))

    @staticmethod
    def _send_message(connection: socket.socket, value: Mapping[str, Any]) -> None:
        connection.sendall(encode_connector_message(value))

    def _send_error(self, connection: socket.socket, message: str) -> None:
        try:
            self._send_message(
                connection,
                {"type": "error", "abi": CONNECTOR_ABI_VERSION, "error": message},
            )
        except OSError:
            pass

    def _handle_connection(self, connection: socket.socket) -> None:
        with connection:
            if not self._peer_is_current_user(connection):
                self._send_error(connection, "local connector peer is not authorized")
                return
            buffered = bytearray()
            try:
                hello = self._receive_message(connection, buffered)
                if hello.get("type") != "hello":
                    raise ConnectorError("connector hello is required")
                token = hello.get("token")
                connector_id = _validate_identifier(hello.get("connector_id"), CONNECTOR_ID_RE, "ID")
                lanes = validate_connector_lanes(hello.get("lanes"))
                if not isinstance(token, str) or not hmac.compare_digest(token, self.token):
                    raise ConnectorError("invalid local connector capability")
                accepted = [lane for lane in lanes if lane in self.lane_handlers]
                self._send_message(
                    connection,
                    {
                        "type": "hello_ack",
                        "abi": CONNECTOR_ABI_VERSION,
                        "connector_id": connector_id,
                        "lanes": accepted,
                    },
                )
                while not self.stop_event.is_set():
                    message = self._receive_message(connection, buffered)
                    link_id, lane, payload, message_id = decode_connector_frame(message)
                    handler = self.lane_handlers.get(lane)
                    if handler is None:
                        raise ConnectorError("connector lane is not available")
                    response = handler(connector_id, link_id, lane, payload)
                    if response is not None and (
                        not isinstance(response, bytes) or len(response) > CONNECTOR_MAX_FRAME_BYTES
                    ):
                        raise ConnectorError("connector response exceeds its byte limit")
                    ack: dict[str, Any] = {
                        "type": "frame_ack",
                        "abi": CONNECTOR_ABI_VERSION,
                        "link_id": link_id,
                        "lane": lane,
                    }
                    if message_id:
                        ack["message_id"] = message_id
                    if response is not None:
                        ack["payload"] = base64.urlsafe_b64encode(response).rstrip(b"=").decode("ascii")
                    self._send_message(connection, ack)
            except ConnectorError as exc:
                self._send_error(connection, str(exc))
            except (OSError, ValueError):
                self._send_error(connection, "invalid local connector request")
            except Exception:
                self._send_error(connection, "local connector request failed")
