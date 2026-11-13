#!/usr/bin/env python3
"""Review check T8: does the tool make sure that it talks to ITS OWN helper node?

cold-address.py picks a free loopback port, closes it, and tells truenorthd to use it. Between those two steps
the port is free. This test plays "another program on the same computer": it waits for the tool's helper
node to appear in the process list (its command line shows the port), takes the port first, and passes
every request on to a second, legitimate node so that all answers are correct. It then reports what it
received. It records only WHETHER a private descriptor arrived, never its content. Dry run on regtest,
throw-away phrase.

usage: t08_port_owner.py SRC BIN WORK
"""
import base64
import hashlib
import re
import http.client
import http.server
import importlib.util
import os
import shutil
import socket
import subprocess
import sys
import threading
import time

SRC, BIN, WORK = sys.argv[1], sys.argv[2], sys.argv[3]
sys.argv = [sys.argv[0], SRC, BIN, WORK, "dry-regtest"]
spec = importlib.util.spec_from_file_location("t04", os.path.join(os.path.dirname(os.path.abspath(__file__)), "t04_trace.py"))
t04 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t04)

seen = {"requests": 0, "methods": [], "private_descriptor": 0, "with_credentials": 0}
backend = {}


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        seen["requests"] += 1
        seen["with_credentials"] += 1 if self.headers.get("Authorization") else 0
        for m in (b"getblockcount", b"deriveaddresses", b"stop"):
            if b'"method":"' + m in body.replace(b" ", b""):
                seen["methods"].append(m.decode())
        m = re.search(rb"qrh\(([1-9A-HJ-NP-Za-km-z]{100,120})/88h/", body)
        if m:
            key = hashlib.sha256(m.group(1)).hexdigest()        # remember only a fingerprint, never the key
            seen.setdefault("keys", [])
            if key not in seen["keys"]:
                seen["keys"].append(key)
            # the first key the tool ever sends is the public known-answer phrase; any other one is the user's
            if seen["keys"].index(key) > 0:
                seen["private_descriptor"] += 1
        if b'"method":"stop"' in body.replace(b" ", b""):
            out = b'{"result":"TrueNorth Core stopping","error":null,"id":1}\n'
            code = 200
        else:
            c = http.client.HTTPConnection("127.0.0.1", backend["port"], timeout=30)
            c.request("POST", "/", body, {"Authorization": "Basic " + backend["auth"], "Content-Type": "application/json"})
            r = c.getresponse()
            out, code = r.read(), r.status
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


_known = set()


def find_tool_node(tmp):
    """Look only at processes that appeared since the last call, so that the reaction time stays near 1 ms."""
    for pid in os.listdir("/proc"):
        if pid.isdigit() and pid not in _known:
            try:
                cmd = open("/proc/%s/cmdline" % pid, "rb").read().decode("utf-8", "replace").split("\0")
            except OSError:
                continue
            if cmd and cmd[0].endswith("truenorthd") and any(tmp in a for a in cmd):
                for a in cmd:
                    if a.startswith("-rpcport="):
                        return int(pid), int(a.split("=")[1])
            if cmd and cmd[0] and "cold-address.py" not in " ".join(cmd):
                _known.add(pid)          # not the node and not a child that is about to become it
    return None, None


def main():
    os.makedirs(WORK, exist_ok=True)
    kit, tmp, btmp = (os.path.join(WORK, n) for n in ("kit-port", "tmp-port", "tmp-backend"))
    for d in (kit, tmp, btmp):
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
    for name in ("cold-address.py", "tn-seed.py", "english.txt"):
        shutil.copy(os.path.join(SRC, name), kit)

    # the second, legitimate node that answers the questions
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    backend["port"] = s.getsockname()[1]
    s.close()
    node = subprocess.Popen([os.path.join(BIN, "truenorthd"), "-datadir=" + btmp, "-chain=regtest", "-listen=0", "-connect=0",
                             "-dnsseed=0", "-fixedseeds=0", "-disablewallet=1", "-server=1", "-rpcbind=127.0.0.1",
                             "-rpcallowip=127.0.0.1", "-rpcport=%d" % backend["port"], "-printtoconsole=0"],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cookie = os.path.join(btmp, "regtest", ".cookie")
    for _ in range(120):
        if os.path.exists(cookie):
            break
        time.sleep(0.25)
    backend["auth"] = base64.b64encode(open(cookie, "rb").read()).decode()
    time.sleep(2)

    result = {}

    def squat():
        end = time.time() + 60
        while time.time() < end:
            pid, port = find_tool_node(tmp)
            if port:
                try:
                    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
                    result.update(pid=pid, port=port, took=True, srv=srv)
                    srv.serve_forever()
                except OSError:
                    result.update(pid=pid, port=port, took=False)
                return

    th = threading.Thread(target=squat, daemon=True)
    th.start()

    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "TERM": "xterm-256color", "TN_BIN": BIN, "TMPDIR": tmp, "HOME": tmp}
    sess = t04.Session([sys.executable, os.path.join(kit, "cold-address.py"), "--dry-run", "--chain", "regtest"], env)
    outcome = "?"
    try:
        sess.expect(r"Press Enter to show the 24 words\. |STOP: ", timeout=150)
        if "STOP" in t04.ANSI.sub("", sess.raw):
            outcome = "the tool stopped before the ceremony"
        else:
            sess.send("")
            words = t04.grab_words(sess.expect(r"The words will disappear from the screen\. "))
            sess.send("")
            for i, w in enumerate(words):
                sess.expect(r"%2d: " % (i + 1))
                sess.send(w)
            rc = sess.finish(timeout=120)
            text = t04.ANSI.sub("", sess.raw)
            outcome = "the tool finished with exit code %s and %s" % (
                rc, "printed 'Done.' and a cold address" if "Done." in text else "did not print 'Done.'")
    except AssertionError as e:
        outcome = "the run did not complete: %s" % str(e)[:200]
    tool_node_alive = result.get("pid") and os.path.exists("/proc/%s" % result["pid"]) and \
        "truenorthd" in open("/proc/%s/cmdline" % result["pid"]).read()
    print("Review check T8, cold-address.py sha256 of the tested copy: see FILES.sha256 (version 1.1)")
    print("  another program took the tool's RPC port before the tool's own node could: %s" % result.get("took"))
    print("  outcome for the user: %s" % outcome)
    print("  requests the other program received from the tool: %d (%s)" % (seen["requests"], ", ".join(seen["methods"])))
    print("  of these, sent with the tool's RPC credentials attached: %d" % seen["with_credentials"])
    print("  requests that carried the PRIVATE descriptor of the user's new words: %d" % seen["private_descriptor"])
    print("  the tool's own helper node at the end: %s" % ("still running" if tool_node_alive else "not running (it could not open its port and quit)"))
    leaked = seen["private_descriptor"] > 0
    print("RESULT", "LEAK: the private descriptor reached a program that is not the tool's own node" if leaked else "OK: no private descriptor reached the other program")
    if result.get("srv"):
        result["srv"].shutdown()
    node.terminate()
    try:
        node.wait(timeout=30)
    except Exception:
        node.kill()
    for d in (tmp, btmp):
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    main()
