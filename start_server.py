"""
TRUSTNOX Prototype Web Server Launcher
======================================
Starts a local HTTP server and automatically opens the TRUSTNOX prototype
in the default web browser.
"""

import http.server
import socketserver
import webbrowser
import os
import sys

PORT = 8080
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

def start_server():
    os.chdir(DIRECTORY)
    # Find free port if 8080 is busy
    port = PORT
    max_attempts = 10
    httpd = None

    for attempt in range(max_attempts):
        try:
            httpd = socketserver.TCPServer(("", port), Handler)
            break
        except OSError:
            port += 1

    if not httpd:
        print(f"[!] Could not bind to ports {PORT}-{PORT + max_attempts}. Please check running processes.")
        return

    url = f"http://localhost:{port}/index.html"
    print("\n" + "=" * 70)
    print("  TRUSTNOX — Detecting Excessive Cloud Permissions")
    print("=" * 70)
    print(f"  [+] Local Prototype Server running at: {url}")
    print(f"  [+] Serving directory: {DIRECTORY}")
    print("  [+] Press Ctrl+C in terminal to stop server.")
    print("=" * 70 + "\n")

    try:
        webbrowser.open(url)
    except Exception as e:
        print(f"  [*] Could not automatically launch browser: {e}")
        print(f"  [*] Please open {url} manually in your web browser.")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  [*] Shutting down TRUSTNOX server.")
        httpd.server_close()

if __name__ == "__main__":
    start_server()
