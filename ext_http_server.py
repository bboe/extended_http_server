"""A small set of improvements upon the Simple and BaseHTTPServers."""

from __future__ import annotations

import argparse
import base64
import errno
import io
import os
import socketserver
import ssl
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer, SimpleHTTPRequestHandler
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TYPE_CHECKING, Any, AnyStr, ClassVar, cast
from warnings import warn

if TYPE_CHECKING:
    from socket import socket

    from _typeshed import SupportsRead, SupportsWrite

try:
    __version__ = version("ext_http_server")
except PackageNotFoundError:  # running from a source checkout without an install
    __version__ = "unknown"


class AuthHandler(SimpleHTTPRequestHandler):
    """A handler that supports basic HTTP authentication/authorization."""

    message = "Authentication required."
    realm = "Something"
    users: ClassVar[set[str]] = set()

    @classmethod
    def add_user(cls, username: str, password: str) -> None:
        """Add a set of credentials."""
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        cls.users.add(token)

    def do_GET(self) -> None:
        """Call the parent's do_GET function if the user is authorized."""
        if self.handle_auth():
            super().do_GET()

    def do_HEAD(self) -> None:
        """Call the parent's do_HEAD function if the user is authorized."""
        if self.handle_auth(head=True):
            super().do_HEAD()

    def handle_auth(self, *, head: bool = False) -> bool:
        """Output the authentication headers if the user is not valid.

        Returns:
            ``True`` when the request carries valid credentials, ``False`` otherwise.

        """
        if auth := self.headers.get("Authorization"):
            try:
                _, encoded = auth.split(" ", 1)
            except ValueError:
                encoded = None
            # Verify the user
            if encoded in AuthHandler.users:
                return True
        # Send authentication header information
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("WWW-Authenticate", f'Basic realm="{AuthHandler.realm}"')
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(AuthHandler.message)))
        self.end_headers()
        if not head:
            self.wfile.write(AuthHandler.message.encode())
        return False


class RangeHandler(SimpleHTTPRequestHandler):
    """A handler that supports HTTP requests with the Range header.

    The Range header allows for the resume download functionality.

    """

    is_ranged: bool
    range_begin: int
    range_end: int | None

    def copyfile(self, source: SupportsRead[AnyStr], outputfile: SupportsWrite[AnyStr]) -> None:
        """Copy only the ranged part of the file when appropriate."""
        if self.is_ranged and isinstance(source, io.IOBase):
            source.seek(self.range_begin)
        super().copyfile(source, outputfile)

    def do_GET(self) -> None:
        """Set is_ranged flag if a valid Range header is sent."""
        self.handle_range()
        super().do_GET()

    def do_HEAD(self) -> None:
        """Set is_ranged flag if a valid Range header is sent."""
        self.handle_range()
        super().do_HEAD()

    def handle_range(self) -> None:
        """Parse the Range header if it exists."""
        self.is_ranged = False
        raw = self.headers.get("range")
        if not raw or "=" not in raw:
            return
        range_unit, _, other = raw.partition("=")
        if range_unit != "bytes" or "-" not in other:
            return
        if "," in other:  # Handle only a single range
            warn("Multiple ranges are not supported.", stacklevel=2)
            return
        begin, _, end = other.partition("-")
        if end:
            warn("Shortened ranges are not supported.", stacklevel=2)
            return
        if begin and not begin.isdigit():
            return
        self.range_begin = int(begin) if begin else 0
        self.range_end = None
        self.is_ranged = True

    def send_header(self, keyword: str, value: str) -> None:
        """Modify Content-Length and add Content-Range when ranged."""
        if keyword == "Content-Length" and self.is_ranged:
            length = int(value)
            end = length - 1 if self.range_end is None else min(self.range_end, length - 1)
            value = str(1 + end - self.range_begin)
            self.send_header("Content-Range", f"bytes {self.range_begin}-{end}/{length}")
        super().send_header(keyword, value)

    def send_response(self, code: int, message: str | None = None) -> None:
        """Send 206 status for ranged responses."""
        if self.is_ranged and code == HTTPStatus.OK:
            code = HTTPStatus.PARTIAL_CONTENT
        super().send_response(code, message)

    def setup(self) -> None:
        """Set HTTP/1.1 as Range is supported only on HTTP/1.1."""
        super().setup()
        self.protocol_version = "HTTP/1.1"
        self.is_ranged = False


class RateLimitHandler(SimpleHTTPRequestHandler):
    """A handler that supports rate limiting from server to client.

    This handler will not properly rate limit if a ForkingMixIn is used in the
    HTTPServer object. However, it works great in combination with the ThreadingMixIn.

    """

    def handle(self) -> None:
        """Set up rate limiting on the outgoing connection."""
        # RateLimitWriter is a transparent write-proxy, not a BufferedIOBase subclass.
        self.wfile = cast("io.BufferedIOBase", RateLimitWriter(self.wfile))
        super().handle()


class MyHandler(AuthHandler, RangeHandler, RateLimitHandler):
    """A handler that supports auth, download resuming, and throttling."""


class RateLimitWriter:
    """A class that rate limits writing to associated file streams.

    This method only supports threading and not forking (multiprocessing).

    """

    INTERVAL_LEN: ClassVar[float] = 0.125
    block_sent: ClassVar[int] = 0
    block_size: ClassVar[int] = 16384
    block_start: ClassVar[float] = 0.0
    lock: ClassVar = threading.Lock()

    wrapped: io.BufferedIOBase

    @classmethod
    def bytes_to_write(cls, desired: int) -> int:
        """Determine how many bytes to write and sleep when over the limit.

        Returns:
            The number of bytes the caller may write now.

        """
        to_send = 0
        while not to_send:
            with cls.lock:
                now = time.time()
                if not cls.block_start:
                    # First data of block, send it all
                    cls.block_start = now
                    to_send = min(desired, cls.block_size)
                    cls.block_sent = to_send
                elif cls.block_sent < cls.block_size:
                    # Haven't sent a complete block, send remainder
                    to_send = min(desired, cls.block_size - cls.block_sent)
                    cls.block_sent += to_send
                else:
                    # A complete block has been sent, sleep if necessary
                    sleep_time = cls.INTERVAL_LEN - (now - cls.block_start)
                    if sleep_time > 0:
                        time.sleep(sleep_time)
                    cls.block_start = 0.0
                    cls.block_sent = 0
        return to_send

    @classmethod
    def set_rate_limit(cls, limit: float) -> None:
        """Set the rate limit in kilobytes per second."""
        cls.block_size = int(1024 * limit * cls.INTERVAL_LEN)

    def __getattr__(self, attr: str) -> Any:  # noqa: ANN401
        """Redirect all attribute access to the wrapped output stream.

        Returns:
            The corresponding attribute of the wrapped stream.

        """
        return getattr(self.wrapped, attr)

    def __init__(self, to_wrap: io.BufferedIOBase) -> None:
        """Store the output stream we are wrapping."""
        self.wrapped = to_wrap

    def write(self, message: bytes) -> None:
        """Perform a throttled write to the wrapped output stream."""
        while message:
            to_send = RateLimitWriter.bytes_to_write(len(message))
            self.wrapped.write(message[:to_send])
            message = message[to_send:]


class SecureHTTPServer(HTTPServer):
    """A HTTP Server object that supports HTTPS."""

    def __init__(
        self,
        address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        cert_file: str | os.PathLike[str],
    ) -> None:
        """Support TLS/SSL by wrapping the socket."""
        super().__init__(address, handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file)
        self.socket = context.wrap_socket(self.socket, server_side=True)


class MyServer(socketserver.ThreadingMixIn, SecureHTTPServer):
    """A threaded SecureHTTPServer with basic error filtering."""

    def handle_error(self, request: socket | tuple[bytes, socket], client_address: Any) -> None:  # noqa: ANN401
        """Disable tracebacks on connection close errors."""
        _, exc_value, _ = sys.exc_info()
        if isinstance(exc_value, OSError) and exc_value.errno == errno.EPIPE:
            print(f"{client_address} closed connection")
        elif isinstance(exc_value, ssl.SSLError) and exc_value.errno == 1:
            print(f"{client_address} SSL Error: bad write retry")
        else:
            super().handle_error(request, client_address)


def main() -> int:
    """Run a secure threaded server with auth resume and rate limit support.

    Returns:
        The process exit status.

    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-p", "--port", default=8000, type=int)
    parser.add_argument("-c", "--cert", help="The TLS/SSL certificate file")
    parser.add_argument("-d", "--directory", help="The directory to serve")
    parser.add_argument("-r", "--ratelimit", default=128, help="The ratelimit in KBps", type=int)
    parser.add_argument("-a", "--add-auth", action="append", help="Add user:password combination")
    options = parser.parse_args()

    # Configure Services
    if not options.add_auth:
        parser.error("At least one user must be added via --add-auth")
    for auth in options.add_auth:
        try:
            username, password = auth.split(":", 1)
        except ValueError:
            parser.error(f"{auth!r} is not a valid username:password")
        AuthHandler.add_user(username, password)
    RateLimitWriter.set_rate_limit(options.ratelimit)

    # Verify cert file
    if not options.cert:
        parser.error("--cert must be provided")
    cert_path = Path(options.cert).resolve()
    if not cert_path.is_file():
        parser.error("Invalid cert file")

    # Change into serving directory
    if options.directory:
        try:
            os.chdir(options.directory)
        except OSError:
            parser.error("Invalid --directory")

    server = MyServer(("", options.port), MyHandler, cert_path)
    print(f"Server listening on port {options.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nGoodbye")
    return 0


if __name__ == "__main__":
    sys.exit(main())
