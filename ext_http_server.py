#!/usr/bin/env python
"""A small set of improvements upon the Simple and BaseHTTPServers."""

import SocketServer
import base64
import os
import socket
import ssl
import sys
import threading
import time
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SimpleHTTPServer import SimpleHTTPRequestHandler
from optparse import OptionParser
from warnings import warn


__version__ = '0.2'


#
# Helpers
#
class RateLimitWriter(object):
    """A class that rate limits writing to associated file streams

    This method only supports threading and not forking (multiprocessing).
    """
    INTERVAL_LEN = .125
    block_size = 16384
    lock = threading.Lock()
    block_start = None
    block_sent = 0

    @classmethod
    def bytes_to_write(cls, desired):
        """Determine how many bytes to write and sleep when over the limit."""
        to_send = 0
        while not to_send:
            cls.lock.acquire()
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
                cls.block_start = cls.block_sent = None
                cls.block_sent = 0
            cls.lock.release()
        return to_send

    @classmethod
    def set_rate_limit(cls, limit):
        """Set the rate limit in kilobytes per second."""
        cls.block_size = int(1024 * limit * cls.INTERVAL_LEN)

    def __init__(self, to_wrap):
        """Store the output stream we are wrapping."""
        self.wrapped = to_wrap

    def __getattr__(self, attr):
        """Redirect all function calls through the wrapped output stream."""
        return getattr(self.wrapped, attr)

    def write(self, message):
        """Perform a throttled write to the wrapped output stream."""
        while message:
            to_send = RateLimitWriter.bytes_to_write(len(message))
            self.wrapped.write(message[:to_send])
            message = message[to_send:]


#
# HTTPServer extensions
#
class SecureHTTPServer(HTTPServer, object):
    """A HTTP Server object that support HTTPS"""
    def __init__(self, address, handler, cert_file):
        """Support TLS/SSL by wrapping the socket."""
        super(SecureHTTPServer, self).__init__(address, handler)
        self.socket = ssl.wrap_socket(self.socket, certfile=cert_file)


#
# BaseHTTPRequestHandler extensions
#
class AuthHandler(BaseHTTPRequestHandler, object):
    """A handler that supports basic HTTP authentication/authorization"""
    message = 'Authentication required.'
    realm = 'Something'
    users = set()

    @classmethod
    def add_user(cls, username, password):
        """Add a set of credentials."""
        cls.users.add(base64.b64encode('{}:{}'.format(username, password)))

    def handle_auth(self, head=False):
        """Output the authentication headers if the user is not valid."""
        auth = self.headers.getheader('Authorization')
        if auth:
            try:
                _, encoded = auth.split(' ', 1)
            except ValueError:
                encoded = None
            # Verify the user
            if encoded in AuthHandler.users:
                return True
        # Send authentication header information
        self.send_response(401)
        self.send_header('WWW-Authenticate',
                         'Basic realm="{0}"'.format(AuthHandler.realm))
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', len(AuthHandler.message))
        self.end_headers()
        if not head:
            self.wfile.write(AuthHandler.message)
        return False

    def do_GET(self):
        """Call the parent's do_GET function if the user is authorized."""
        if self.handle_auth():
            super(AuthHandler, self).do_GET()

    def do_HEAD(self):
        """Call the parent's do_HEAD function if the user is authorized."""
        if self.handle_auth(head=True):
            super(AuthHandler, self).do_HEAD()


class RangeHandler(SimpleHTTPRequestHandler, object):
    """A handler that supports HTTP requests with the Range header

    The Range header allows for the resume download functionality.
    """
    def copyfile(self, source, outputfile):
        """Copy only the ranged part of the file when appropriate."""
        if self.is_ranged:
            source.seek(self.range_begin)
        super(RangeHandler, self).copyfile(source, outputfile)

    def do_GET(self):
        """Set is_ranged flag if a valid Range header is sent."""
        self.handle_range()
        super(RangeHandler, self).do_GET()

    def do_HEAD(self):
        """Set is_ranged flag if a valid Range header is sent."""
        self.handle_range()
        super(RangeHandler, self).do_HEAD()

    def handle_range(self):
        """Parse the Range header if it exists."""
        self.is_ranged = False
        if 'range' in self.headers:
            try:
                range_unit, other = self.headers['range'].split('=', 1)
                if range_unit == 'bytes':
                    if ',' in other:  # Handle only a single range
                        warn('Multiple ranges are not supported.')
                        return
                    begin, end = other.split('-', 1)
                    if end:
                        warn('Shortened ranges are not supported.')
                        return
                    self.range_begin = int(begin) if begin else 0
                    self.range_end = None
                    self.is_ranged = True
            except ValueError:
                pass

    def send_header(self, key, value):
        """Modify Content-Length and add Content-Range when ranged."""
        if key == 'Content-Length' and self.is_ranged:
            length = int(value)
            if self.range_end is None:
                end = length - 1
            else:
                end = min(self.range_end, length - 1)
            value = str(1 + end - self.range_begin)
            self.send_header('Content-Range', 'bytes {0}-{1}/{2}'
                             .format(self.range_begin, end, length))
        super(RangeHandler, self).send_header(key, value)

    def send_response(self, status, *args, **kwargs):
        """Send 206 status for ranged responses."""
        if self.is_ranged and status == 200:
            status = 206
        super(RangeHandler, self).send_response(status, *args, **kwargs)

    def setup(self):
        """Set HTTP/1.1 as Range is supported only on HTTP/1.1."""
        super(RangeHandler, self).setup()
        self.protocol_version = 'HTTP/1.1'
        self.is_ranged = False


class RateLimitHandler(BaseHTTPRequestHandler, object):
    """A hander that supports rate limiting from server to client.

    This handler will not properly rate limit if a ForkinMixIn is used in the
    HTTPServer object. However, it works great in combination with the
    ThreadingMixIn.
    """
    def handle(self):
        """Setup rate limiting on the outgoing connection."""
        self.wfile = RateLimitWriter(self.wfile)
        super(RateLimitHandler, self).handle()


#
# Combined classes for use with the main functionality
#
class MyHandler(AuthHandler, RangeHandler, RateLimitHandler):
    """A handler that supports auth, download resuming, and throttling."""


class MyServer(SocketServer.ThreadingMixIn, SecureHTTPServer):
    """A threaded SecureHTTPServer with basic error filtering"""
    def handle_error(self, request, client_address):
        """Disable trackebacks on connection close errors."""
        exc_type, exc_value, _ = sys.exc_info()
        if exc_type is socket.error and exc_value[0] == 32:
            print('{0} closed connection'.format(client_address))
        elif exc_type is ssl.SSLError and exc_value.errno == 1:
            print('{0} SSL Error: bad write retry'.format(client_address))
        else:
            super(MyServer, self).handle_error(request, client_address)


def main():
    """Run a secure threaded server with auth resume and rate limit support."""
    parser = OptionParser(version='%prog {0}'.format(__version__))
    parser.add_option('-p', '--port', type='int', default='8000')
    parser.add_option('-c', '--cert', help='The TLS/SSL certificate file')
    parser.add_option('-d', '--directory', help='The directory to serve')
    parser.add_option('-r', '--ratelimit', help='The ratelimit in KBps',
                      type='int', default=128)
    parser.add_option('-a', '--add-auth', help='Add user:password combination',
                      action='append')
    options, _ = parser.parse_args()

    # Configure Services
    if not options.add_auth:
        parser.error('At least one user must be added via --add-auth')
    for auth in options.add_auth:
        try:
            username, password = auth.split(':', 1)
        except ValueError:
            parser.error('{0!r} is not a valid username:password'.format(auth))
        AuthHandler.add_user(username, password)
    RateLimitWriter.set_rate_limit(options.ratelimit)

    # Verify cert file
    if not options.cert:
        parser.error('--cert must be provided')
    cert_path = os.path.abspath(options.cert)
    if not os.path.isfile(cert_path):
        parser.error('Invalid cert file')

    # Change into serving directory
    if options.directory:
        try:
            os.chdir(options.directory)
        except OSError:
            parser.error('Invalid --directory')

    server = MyServer(('', options.port), MyHandler, cert_path)
    print('Server listening on port %d' % options.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nGoodbye')


if __name__ == '__main__':
    sys.exit(main())
