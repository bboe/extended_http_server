import base64
import http.client
import io
import ssl
import threading
from collections.abc import Iterator
from email.message import Message

import pytest
import trustme

from ext_http_server import AuthHandler, MyHandler, MyServer, RangeHandler, RateLimitWriter


@pytest.fixture(autouse=True)
def _reset_global_state() -> Iterator[None]:
    AuthHandler.users.clear()
    RateLimitWriter.block_start = 0.0
    RateLimitWriter.block_sent = 0
    RateLimitWriter.block_size = 16384
    yield
    AuthHandler.users.clear()


@pytest.fixture
def secure_server(tmp_path, monkeypatch) -> Iterator[tuple[int, ssl.SSLContext]]:
    (tmp_path / "data.txt").write_text("0123456789ABCDEFGHIJ")
    monkeypatch.chdir(tmp_path)
    authority = trustme.CA()
    server_cert = authority.issue_cert("127.0.0.1")
    with server_cert.private_key_and_cert_chain_pem.tempfile() as cert_path:
        AuthHandler.add_user("user", "pass")
        server = MyServer(("127.0.0.1", 0), MyHandler, cert_path)
        thread = threading.Thread(daemon=True, target=server.serve_forever)
        thread.start()
        client_context = ssl.create_default_context()
        authority.configure_trust(client_context)
        try:
            yield server.server_address[1], client_context
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


def build_range_handler(range_value=None):
    handler = object.__new__(RangeHandler)
    headers = Message()
    if range_value is not None:
        headers["Range"] = range_value
    handler.headers = headers
    return handler


def request_file(port, client_context, *, authenticate=False, range_header=None):
    connection = http.client.HTTPSConnection("127.0.0.1", port, context=client_context)
    headers = {}
    if authenticate:
        headers["Authorization"] = "Basic " + base64.b64encode(b"user:pass").decode()
    if range_header:
        headers["Range"] = range_header
    try:
        connection.request("GET", "/data.txt", headers=headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def test_add_user_stores_base64_token():
    AuthHandler.add_user("user", "pass")
    assert base64.b64encode(b"user:pass").decode() in AuthHandler.users


def test_bytes_to_write_caps_to_remaining_block():
    RateLimitWriter.block_size = 100
    RateLimitWriter.block_start = 0.0
    RateLimitWriter.block_sent = 0
    assert RateLimitWriter.bytes_to_write(10) == 10  # first write, under the block size
    assert RateLimitWriter.bytes_to_write(2) == 2  # still within the block
    assert RateLimitWriter.bytes_to_write(1000) == 88  # capped to what remains of the block


def test_handle_range_absent():
    handler = build_range_handler()
    handler.handle_range()
    assert handler.is_ranged is False


def test_handle_range_multiple_warns():
    handler = build_range_handler("bytes=0-0,2-2")
    with pytest.warns(UserWarning, match="Multiple ranges"):
        handler.handle_range()
    assert handler.is_ranged is False


@pytest.mark.parametrize("range_value", ["bytes=5-9", "bytes=-100"])
def test_handle_range_shortened_warns(range_value):
    handler = build_range_handler(range_value)
    with pytest.warns(UserWarning, match="Shortened ranges"):
        handler.handle_range()
    assert handler.is_ranged is False


@pytest.mark.parametrize("range_value", ["bytes=5", "items=5-", "bytes=a-", "kbytes=0-"])
def test_handle_range_unsupported_is_silent(range_value, recwarn):
    handler = build_range_handler(range_value)
    handler.handle_range()
    assert handler.is_ranged is False
    assert not recwarn.list


@pytest.mark.parametrize(
    ("range_value", "expected_begin"),
    [("bytes=5-", 5), ("bytes=0-", 0), ("bytes=12-", 12)],
)
def test_handle_range_valid(range_value, expected_begin):
    handler = build_range_handler(range_value)
    handler.handle_range()
    assert handler.is_ranged is True
    assert handler.range_begin == expected_begin
    assert handler.range_end is None


def test_rate_limit_writer_delegates_unknown_attributes():
    sink = io.BytesIO()
    writer = RateLimitWriter(sink)
    writer.flush()  # proxied to the wrapped stream via __getattr__
    assert writer.closed is sink.closed


def test_rate_limit_writer_proxies_all_bytes():
    RateLimitWriter.block_size = 10**9  # large enough to avoid throttling/sleeping
    sink = io.BytesIO()
    RateLimitWriter(sink).write(b"hello world")
    assert sink.getvalue() == b"hello world"


def test_server_requires_authentication(secure_server):
    port, context = secure_server
    status, _ = request_file(port, context)
    assert status == 401


def test_server_serves_authenticated_request(secure_server):
    port, context = secure_server
    status, body = request_file(port, context, authenticate=True)
    assert status == 200
    assert body == b"0123456789ABCDEFGHIJ"


def test_server_serves_range_request(secure_server):
    port, context = secure_server
    status, body = request_file(port, context, authenticate=True, range_header="bytes=5-")
    assert status == 206
    assert body == b"56789ABCDEFGHIJ"


def test_set_rate_limit_computes_block_size():
    RateLimitWriter.set_rate_limit(128)
    assert RateLimitWriter.block_size == int(1024 * 128 * RateLimitWriter.INTERVAL_LEN)
