"""Controlled loopback HTTPS Git endpoint for browser source-sync acceptance."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import ssl
import subprocess
import time
from urllib.parse import unquote


class GitHttpHandler(BaseHTTPRequestHandler):
    server_version = "ohscanner-browser-git-fixture"
    protocol_version = "HTTP/1.1"

    def _handle(self):
        if self.server.slow:
            time.sleep(3600)
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        parsed_path = unquote(self.path.split("?", 1)[0])
        query = self.path.split("?", 1)[1] if "?" in self.path else ""
        env = {
            **os.environ,
            "GIT_PROJECT_ROOT": str(self.server.git_root),
            "GIT_HTTP_EXPORT_ALL": "1",
            "PATH_INFO": parsed_path,
            "QUERY_STRING": query,
            "REQUEST_METHOD": self.command,
            "CONTENT_TYPE": self.headers.get("Content-Type", ""),
            "CONTENT_LENGTH": str(length),
            "REMOTE_ADDR": "127.0.0.1",
            "REMOTE_USER": "browser-acceptance",
            "SERVER_PROTOCOL": "HTTP/1.1",
            "GATEWAY_INTERFACE": "CGI/1.1",
            "SERVER_NAME": "127.0.0.1",
            "SERVER_PORT": str(self.server.server_port),
        }
        done = subprocess.run(
            ["/usr/lib/git-core/git-http-backend"],
            input=body,
            capture_output=True,
            env=env,
            check=False,
        )
        raw = done.stdout
        split = raw.find(b"\r\n\r\n")
        if done.returncode or split < 0:
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(done.stderr or raw)
            return
        headers = {}
        status = 200
        for line in raw[:split].decode("utf-8", "replace").split("\r\n"):
            if line.startswith("Status:"):
                status = int(line[7:].strip().split(" ", 1)[0])
            elif ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()
        body = raw[split + 4 :]
        self.send_response(status)
        headers["Content-Length"] = str(len(body))
        headers["Connection"] = "close"
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    do_GET = _handle
    do_POST = _handle
    do_HEAD = _handle


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--slow", action="store_true")
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), GitHttpHandler)
    server.daemon_threads = True
    server.git_root = args.root.resolve()
    server.slow = args.slow
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        str(server.git_root / "cert.pem"),
        str(server.git_root / "key.pem"),
    )
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"git fixture listening on 127.0.0.1:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
