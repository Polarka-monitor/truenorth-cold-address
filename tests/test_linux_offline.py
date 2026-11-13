#!/usr/bin/env python3
"""The offline check in real conditions, and a whole REAL run (not a dry run) with no network at all.

  python3 tests/test_linux_offline.py

Linux only. Needs root and the commands unshare, nsenter and ip, because each case runs in a network
namespace of its own that the test wires up. Anywhere else the test says so and is skipped.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

PRIVATE_TMP = tempfile.mkdtemp(prefix="coldtest-")
os.environ["TMPDIR"] = tempfile.tempdir = PRIVATE_TMP

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ptydriver as pd   # noqa: E402

if not sys.platform.startswith("linux") or os.geteuid() != 0 or not all(shutil.which(c) for c in ("unshare", "nsenter", "ip")) \
        or subprocess.run(["unshare", "-n", "-m", "sh", "-c", "mount -t sysfs sysfs /sys"], capture_output=True).returncode != 0:
    print("SKIP  needs Linux, root and the commands unshare, nsenter and ip")
    shutil.rmtree(PRIVATE_TMP, ignore_errors=True)
    sys.exit(0)

tool = pd.load_tool()
BIN = tool.find_bin()
failed = []
# A new network namespace needs its own view of /sys, or the interfaces of the host would still be listed there.
LO = "mount -t sysfs sysfs /sys; ip link set lo up; "
LINK = LO + ("ip link add eth9 type veth peer name eth9p; ip addr add 192.168.50.2/24 dev eth9; "
             "ip link set eth9 up; ip link set eth9p up; ")
PROBE = "import importlib.util, json, sys\n" \
        "spec = importlib.util.spec_from_file_location('coldaddress', sys.argv[1])\n" \
        "tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)\n" \
        "print(json.dumps(tool.net_status()))\n"


def check(name, ok, detail=""):
    print("%s  %s%s" % ("PASS" if ok else "FAIL", name, ("   [" + detail + "]") if detail and not ok else ""))
    if not ok:
        failed.append(name)


def status(setup):
    r = subprocess.run(["unshare", "-n", "-m", "sh", "-c", setup + 'exec "$0" -I -c "$1" "$2"', sys.executable, PROBE,
                        os.path.join(pd.ROOT, "cold-address.py")], capture_output=True, text=True)
    return json.loads(r.stdout.splitlines()[-1])


def real(kit, args, setup=LO):
    """The tool as a real run on a terminal of its own, inside a new network namespace."""
    return pd.Session(kit, [], BIN, argv=["unshare", "-n", "-m", "sh", "-c", setup + 'exec "$@"', "sh", sys.executable,
                                          os.path.join(kit, "cold-address.py")] + args)


# 1. What the check sees
reasons, hints = status(LO)
check("only the loopback interface: nothing found", not reasons and not hints, str((reasons, hints)))
reasons, hints = status(LINK)
check("a LAN without a gateway: no route, but the interfaces are named for the user to judge",
      not reasons and hints == ["interface eth9 has a link", "interface eth9p has a link"], str((reasons, hints)))
reasons, hints = status(LINK + "ip route add default via 192.168.50.1; ")
check("a default route: found, with the interface name",
      "default IPv4 route through eth9" in reasons and "the system has a route to public IPv4 addresses" in reasons, str(reasons))
reasons, hints = status(LINK + "ip route add default via 192.168.50.1 table 51820; ip rule add not fwmark 51820 table 51820; ")
check("a default route only in another routing table (policy routing): found by asking the kernel",
      reasons == ["the system has a route to public IPv4 addresses"], str(reasons))
reasons, hints = status(LINK + "ip route add 8.0.0.0/7 via 192.168.50.1; ")
check("a route to a large part of the internet only (8.0.0.0/7): found",
      reasons == ["the system has a route to public IPv4 addresses"], str(reasons))
reasons, hints = status(LINK + "ip route add 0.0.0.0/1 via 192.168.50.1; ip route add 128.0.0.0/1 via 192.168.50.1; ")
check("two half-routes instead of a default route (as VPN programs set them): found",
      "the system has a route to public IPv4 addresses" in reasons, str(reasons))

# 2. A whole real run with no network: mainnet address, then verify
kit = pd.fresh_kit()
s = real(kit, [])
s.expect(r"ok, no network connection found")
s.expect(r"Press Enter to show the 24 words\. ")
s.send("")
words = pd.grab_words(s.expect(r"The words will disappear from the screen\. "))
s.send("")
for i, w in enumerate(words):
    s.expect(r"%2d: " % (i + 1))
    s.send(w)
rc = s.finish()
saved = open(os.path.join(kit, "out", "cold-address.txt")).read().strip() if rc == 0 else ""
check("a real run with no network finishes and saves a mainnet address",
      rc == 0 and saved.startswith("north1z") and saved == tool.py_addresses(pd.load_tool().load_tnseed().bip39_seed(" ".join(words)), "main", 1)[0],
      "exit code %s" % rc)
check("the real run wiped the screen and printed the recipe", s.wiped() and "m/88h/1867h/0h/0/0" in s.buf)
s = real(kit, ["verify"])
s.expect(r"Press Enter\. ")
s.send("")
for i, w in enumerate(words):
    s.expect(r"%2d: " % (i + 1))
    s.send(w)
rc = s.finish()
check("verify as a real run accepts the words", rc == 0 and "OK: the words on your paper" in s.buf, "exit code %s" % rc)
shutil.rmtree(kit)

# 3. A connection that the user must judge
kit = pd.fresh_kit()
s = real(kit, [], LINK)
s.expect(r"interface eth9 has a link")
s.expect(r"type YES and press Enter: ")
s.send("no")
rc = s.finish()
check("a LAN without a gateway: the tool asks, and stops unless the answer is YES", rc == 2 and "Disconnect the device" in s.buf)
s = real(kit, [], LINK)
s.expect(r"type YES and press Enter: ")
s.send("yes")
s.expect(r"ok, no network connection found")
s.expect(r"Press Enter to show the 24 words\. ")

# 4. The network comes up between the check and the words: nothing is shown
subprocess.run(["nsenter", "--net=/proc/%d/ns/net" % s.pid, "ip", "route", "add", "default", "via", "192.168.50.1"], check=True)
s.send("")
rc = s.finish()
check("going online after the check: the tool stops before any word is shown",
      rc == 2 and "The network state changed after the check" in s.buf and "No words were shown" in s.buf
      and pd.ALT_ON not in s.raw, "exit code %s" % rc)
shutil.rmtree(kit)

shutil.rmtree(PRIVATE_TMP, ignore_errors=True)
print()
print("%d check(s) failed: %s" % (len(failed), "; ".join(failed)) if failed else "All checks passed.")
sys.exit(1 if failed else 0)
