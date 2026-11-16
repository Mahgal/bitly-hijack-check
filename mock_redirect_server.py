#!/usr/bin/env python3
"""Local mock redirect server for bitly-hijack-check demos and tests.

Stdlib only (http.server). Two fixtures:

  /clean     -> 302 to https://example.com/
  /hijacked  -> 302 to https://example-secure-login.com/ (a look-alike
                domain used as a phishing-style example; it is only a
                string in a Location header, never fetched)
  /slow      -> sleeps 2s then 200 (used by the timeout test)

Run standalone to serve on a fixed port for manual poking:
    python3 mock_redirect_server.py [port]   (default 8765)
"""

import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class MockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status, headers, body=b""):
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass  # client went away (e.g. a timeout test); not an error

    def do_GET(self):
        if self.path == "/clean":
            self._send(302, {"Location": "https://example.com/"})
        elif self.path == "/hijacked":
            self._send(302, {"Location": "https://example-secure-login.com/"})
        elif self.path == "/slow":
            time.sleep(2)
            self._send(200, {"Content-Type": "text/plain"}, b"slow ok\n")
        elif self.path == "/loop":
            self._send(302, {"Location": "/loop"})
        else:
            self._send(404, {"Content-Type": "text/plain"}, b"not found\n")

    def log_message(self, *args):  # keep test/demo output clean
        pass


def run_server(port=0):
    """Start the mock server on 127.0.0.1. Returns (server, actual_port)."""
    server = ThreadingHTTPServer(("127.0.0.1", port), MockHandler)
    return server, server.server_address[1]


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    port = int(argv[0]) if argv else 8765
    server, actual = run_server(port)
    print("mock redirect server on http://127.0.0.1:%d" % actual)
    print("  /clean     -> https://example.com/")
    print("  /hijacked  -> https://example-secure-login.com/")
    print("  /slow      -> 200 after a 2s delay")
    print("  /loop      -> redirects to itself")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
