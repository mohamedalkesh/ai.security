#!/usr/bin/env python3
from http.server import HTTPServer, SimpleHTTPRequestHandler

class NoCacheHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def log_message(self, format, *args):
        super().log_message(format, *args)

if __name__ == '__main__':
    server = HTTPServer(('127.0.0.1', 5500), NoCacheHandler)
    print("Serving on http://127.0.0.1:5500 (no-cache)")
    server.serve_forever()
