### Installation

    pip install ext_http_server

### Generate a certificate

Run the following to generate cert.pem:

    openssl req -new -x509 -days 365 -nodes -out cert.pem -keyout cert.pem

### Running ext_http_server

If you have files you want to serve in `/tmp/path/to/files/` run the following
to serve them up with a max outgoing throughput of 16KBps:

    ext_http_server --cert cert.pem -d /tmp/path/to/files -r16 -a foo:bar

By default, you will be able to access the webserver at
[https://localhost:8000](https://localhost:8000). To authenticate, use the
username `foo` and the password `bar` as indicated by the `-a foo:bar`
argument. Note that multiple `-a` arguments can be added to add more than one
user.
