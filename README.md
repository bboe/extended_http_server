# ext_http_server

An extended version of Python's `http.server` that turns a simple static file
server into one supporting HTTPS, HTTP Basic authentication, server-to-client
rate limiting, and resumable downloads via HTTP `Range` requests.

### Requirements

`ext_http_server` supports Python 3.10 through 3.14.

### Installation

Install the `ext_http_server` command with [uv](https://docs.astral.sh/uv/):

    uv tool install ext_http_server

### Generate a certificate

Generate a self-signed certificate, writing the private key and certificate
together into `cert.pem` (the single file `--cert` expects). This uses a modern
ECDSA P-256 key, which every common TLS client supports (Ed25519 keys are
newer but are rejected by some clients, including the LibreSSL-based `curl` that
ships with macOS as of June 2026):

    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -noenc -keyout cert.pem -out cert.pem -days 365 -subj "/CN=localhost"

### Running ext_http_server

If you have files you want to serve in `/tmp/path/to/files/` run the following
to serve them up with a max outgoing throughput of 16KBps:

    ext_http_server --cert cert.pem -d /tmp/path/to/files -r16 -a foo:bar

Or run it once without installing:

    uvx ext_http_server --cert cert.pem -d /tmp/path/to/files -r16 -a foo:bar

By default, you will be able to access the webserver at
[https://localhost:8000](https://localhost:8000). To authenticate, use the
username `foo` and the password `bar` as indicated by the `-a foo:bar`
argument. Note that multiple `-a` arguments can be added to add more than one
user.
