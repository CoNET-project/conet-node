"""Serve the test page and collect results posted back by browsers (local test only)."""
import http.server, json, sys, pathlib

PAGE = pathlib.Path(__file__).parent / "index.html"
OUT = pathlib.Path(sys.argv[2])

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(PAGE.read_bytes())

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        r = json.loads(self.rfile.read(n) or b"{}")
        with OUT.open("a") as f:
            f.write(json.dumps(r) + "\n")
        print(("OK  " if r.get("ok") else "FAIL"), r.get("ua", "")[:110], flush=True)
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
