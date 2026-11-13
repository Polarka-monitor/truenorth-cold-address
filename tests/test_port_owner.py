#!/usr/bin/env python3
"""Does the tool make sure that it talks to its own helper node?

  python3 tests/test_port_owner.py

cold-address.py picks a free loopback port, closes it and tells truenorthd to use it. In between the port is
free. This test plays another program on the same computer: it waits for the helper node to show up in the
process list (the command line shows the port), takes the port first, and passes every request on to a
second, real node, so that all answers would be right.

The tool must notice: it must stop before any words are made and must not send a single request to the
stranger. (Version 1.1 did not notice; see SECURITY-REVIEW.md, finding 1.)
"""
import base64
import http.client
import http.server
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

PRIVATE_TMP = tempfile.mkdtemp(prefix="coldtest-")
os.environ["TMPDIR"] = tempfile.tempdir = PRIVATE_TMP

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ptydriver as pd   # noqa: E402

tool = pd.load_tool()
BIN = tool.find_bin()
ROUNDS = 5


class Stranger:
    """Takes the port of the tool's helper node and relays to a real node of its own."""

    def __init__(self, backend_port, backend_auth, watch):
        self.requests, self.took, self.server = [], None, None
        self.backend_port, self.backend_auth, self.watch = backend_port, backend_auth, watch
        self.known = set()
        threading.Thread(target=self.run, daemon=True).start()

    def find(self):
        r = subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True, text=True)
        for ln in r.stdout.splitlines():
            if "truenorthd" in ln and self.watch in ln and "-rpcport=" in ln:
                return int(ln.split("-rpcport=")[1].split()[0])
        return None

    def run(self):
        end = time.time() + 90
        while time.time() < end and self.took is None:
            port = self.find()
            if port:
                stranger = self

                class Handler(http.server.BaseHTTPRequestHandler):
                    def log_message(self, *a):
                        pass

                    def do_POST(self):
                        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                        stranger.requests.append(body)
                        if b'"stop"' in body:                 # do not pass this one on: the real node is needed again
                            status, data = 200, b'{"result":"TrueNorth Core stopping","error":null,"id":1}\n'
                        else:
                            c = http.client.HTTPConnection("127.0.0.1", stranger.backend_port, timeout=30)
                            c.request("POST", "/", body, {"Authorization": "Basic " + stranger.backend_auth})
                            r = c.getresponse()
                            status, data = r.status, r.read()
                        self.send_response(status)
                        self.send_header("Content-Length", str(len(data)))
                        self.end_headers()
                        self.wfile.write(data)

                try:
                    self.server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
                    self.took = True
                    self.server.serve_forever()
                except OSError:
                    self.took = False

    def close(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()


failed = []
backend_dir = tempfile.mkdtemp(prefix="backend-")
s = socket.socket()
s.bind(("127.0.0.1", 0))
backend_port = s.getsockname()[1]
s.close()
backend = subprocess.Popen([os.path.join(BIN, "truenorthd"), "-datadir=" + backend_dir, "-chain=regtest", "-listen=0",
                            "-connect=0", "-dnsseed=0", "-fixedseeds=0", "-disablewallet=1", "-server=1",
                            "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", "-rpcport=%d" % backend_port,
                            "-printtoconsole=0"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
try:
    cookie = os.path.join(backend_dir, "regtest", ".cookie")
    for _ in range(240):
        if os.path.exists(cookie):
            break
        time.sleep(0.25)
    auth = base64.b64encode(open(cookie, "rb").read()).decode()
    time.sleep(2)
    taken = 0
    for n in range(ROUNDS):
        kit = pd.fresh_kit()
        nodes = tempfile.mkdtemp(prefix="toolnodes-")
        stranger = Stranger(backend_port, auth, nodes)
        sess = pd.Session(kit, ["--dry-run", "--chain", "regtest"], BIN, env={"TMPDIR": nodes})
        sess.expect(r"Press Enter to show the 24 words\. |STOP: ")
        reached_words = "Press Enter to show" in sess.raw
        if reached_words:
            sess.key(b"\x03")
        rc = sess.finish()
        stranger.close()
        if stranger.took:
            taken += 1
            ok = not reached_words and rc == 2 and not stranger.requests
            print("%s  round %d: the port was taken by a stranger; the tool %s; requests the stranger got: %d"
                  % ("PASS" if ok else "FAIL", n + 1,
                     "stopped before the ceremony" if not reached_words else "WENT ON to the ceremony",
                     len(stranger.requests)))
            if not ok:
                failed.append("round %d" % (n + 1))
        else:
            print("SKIP  round %d: the tool's own node got the port first (the stranger was too slow)" % (n + 1))
        shutil.rmtree(kit, ignore_errors=True)
        shutil.rmtree(nodes, ignore_errors=True)
    if not taken:
        print("NOTE  the stranger never won the race on this computer, so nothing was proved either way")
finally:
    backend.terminate()
    try:
        backend.wait(timeout=40)
    except Exception:
        backend.kill()
    shutil.rmtree(PRIVATE_TMP, ignore_errors=True)

print()
print("%d round(s) failed: %s" % (len(failed), "; ".join(failed)) if failed else "All checks passed.")
sys.exit(1 if failed else 0)
