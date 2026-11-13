#!/usr/bin/env python3
"""Review check T4: run the UNMODIFIED tool under strace, through a pseudo-terminal, and report

  A. every program that is started, with its arguments and environment
  B. every file that any process opens for writing
  C. where data that contains secret material is written (terminal, pipe, loopback socket, file ...)
  D. every socket that is created and every address that is bound or connected to
  E. what is left on disk afterwards

The phrases are throw-away test phrases made by the tool itself in this run. They are never printed here.

usage: t04_trace.py SRC BIN WORK SCENARIO
  SCENARIO: dry-regtest | dry-main-dice | real-netns
"""
import hashlib
import hmac
import importlib.util
import os
import pty
import re
import select
import shutil
import sys
import time

SRC, BIN, WORK, SCEN = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
PY = sys.executable

spec = importlib.util.spec_from_file_location("coldaddress", os.path.join(SRC, "cold-address.py"))
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
tn = tool.load_tnseed()
WORDS = tn.wordlist()


class Session:
    def __init__(self, argv, env):
        self.buf, self.raw = "", ""
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execvpe(argv[0], argv, env)

    def _read(self):
        try:
            data = os.read(self.fd, 65536).decode("utf-8", "replace")
        except OSError:
            data = ""
        self.raw += data
        self.buf += ANSI.sub("", data)
        return data

    def expect(self, pattern, timeout=240):
        end = time.time() + timeout
        while time.time() < end:
            m = re.search(pattern, self.buf)
            if m:
                seen, self.buf = self.buf[:m.end()], self.buf[m.end():]
                return seen
            if select.select([self.fd], [], [], 0.5)[0] and not self._read():
                break
        raise AssertionError("did not see %r; the screen ended with:\n%s" % (pattern, self.buf[-600:]))

    def send(self, line):
        os.write(self.fd, (line + "\n").encode())

    def finish(self, timeout=240):
        end = time.time() + timeout
        while time.time() < end:
            if select.select([self.fd], [], [], 0.5)[0]:
                if not self._read():
                    break
            else:
                done, status = os.waitpid(self.pid, os.WNOHANG)
                if done:
                    return os.waitstatus_to_exitcode(status)
        return os.waitstatus_to_exitcode(os.waitpid(self.pid, 0)[1])


def grab_words(screen):
    found = dict((int(n), w) for n, w in re.findall(r"(\d{1,2})\. ([a-z]+)", screen))
    assert sorted(found) == list(range(1, 25)), sorted(found)
    return [found[i] for i in range(1, 25)]


def command(kit, tracefile, args, netns):
    inner = ["strace", "-f", "-o", tracefile, "-xx", "-v", "-y", "-yy", "-s", "4000000",
             "-e", "trace=execve,execveat,open,openat,openat2,creat,write,writev,pwrite64,pwritev,pwritev2,sendto,"
                   "sendmsg,sendmmsg,sendfile,socket,connect,bind,listen,getrandom,memfd_create,ptrace,"
                   "process_vm_writev,rename,renameat,renameat2,link,linkat,symlink,symlinkat,copy_file_range,splice",
             PY, os.path.join(kit, "cold-address.py")] + args
    if netns:
        return ["unshare", "-n", "-m", "sh", "-c", 'mount -t sysfs sysfs /sys; ip link set lo up && exec "$@"', "sh"] + inner
    return inner


def run_new(kit, tracefile, args, netns, env, dice=None):
    s = Session(command(kit, tracefile, args, netns), env)
    if dice is not None:
        s.expect(r"Rolls: ")
        s.send(dice)
    s.expect(r"Press Enter to show the 24 words\. ")
    s.send("")
    words = grab_words(s.expect(r"The words will disappear from the screen\. "))
    s.send("")
    for i, w in enumerate(words):
        s.expect(r"%2d: " % (i + 1))
        s.send(w)
    return s.finish(), words, s


def run_verify(kit, tracefile, args, netns, env, words):
    s = Session(command(kit, tracefile, ["verify"] + args, netns), env)
    s.expect(r"Press Enter\. ")
    s.send("")
    for i, w in enumerate(words):
        s.expect(r"%2d: " % (i + 1))
        s.send(w)
    return s.finish(), s


# ------------------------------------------------------------------ secret needles

def needles(words, chain, dice):
    phrase = " ".join(words)
    idx = {w: i for i, w in enumerate(WORDS)}
    n = 0
    for w in words:
        n = n << 11 | idx[w]
    entropy = (n >> 8).to_bytes(32, "big")
    seed = tn.bip39_seed(phrase)
    d = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    version, coin = tn.CHAINS[chain]
    xprv = tn.master_xprv(seed, version)
    desc = tn.descriptors(xprv, coin)
    res = {}

    def add(name, value):
        res[name] = value if isinstance(value, bytes) else value.encode()

    add("whole phrase", phrase)
    for i in range(22):
        add("3 words in a row, spaces (%d)" % (i + 1), " ".join(words[i:i + 3]))
        add("3 words in a row, newlines (%d)" % (i + 1), "\n".join(words[i:i + 3]))
    for i, w in enumerate(words):
        add("numbered word as shown (%d)" % (i + 1), "%2d. %s" % (i + 1, w))
    add("entropy raw", entropy)
    add("entropy hex", entropy.hex())
    add("seed raw", seed)
    add("seed hex", seed.hex())
    add("master key raw", d[:32])
    add("master key hex", d[:32].hex())
    add("master chain code raw", d[32:])
    add("root xprv", xprv)
    add("root xprv without the last 6 characters", xprv[:-6])
    add("receive descriptor", desc[0]["desc"])
    k, c = int.from_bytes(d[:32], "big"), d[32:]
    path = "m"
    for i, label in ((88 | 0x80000000, "88h"), (coin | 0x80000000, "%dh" % coin), (0x80000000, "0h"), (0, "0")):
        k, c = tool._ckd(k, c, i)
        path += "/" + label
        add("private key %s raw" % path, k.to_bytes(32, "big"))
        add("private key %s hex" % path, "%064x" % k)
    for i in range(5):
        ki, _ = tool._ckd(k, c, i)
        add("private key %s/%d raw" % (path, i), ki.to_bytes(32, "big"))
        add("private key %s/%d hex" % (path, i), "%064x" % ki)
    if dice:
        add("dice rolls", dice)
    return res


# ------------------------------------------------------------------ trace analysis

STR = re.compile(r'"((?:\\x[0-9a-f]{2})*)"(\.\.\.)?')
HEAD = re.compile(r"^(\d+)\s+(?:<\.\.\. )?(\w+)(?:\(| resumed>)")
FD = re.compile(r"^\d+\s+\w+\((\d+)<([^>]*(?:<[^>]*>)?[^>]*)>")


def unhex(s):
    return bytes.fromhex(s.replace("\\x", ""))


def target_class(desc, kit, tmpdir):
    desc = re.sub(r"((?:\\x[0-9a-f]{2})+)", lambda m: unhex(m.group(1)).decode("utf-8", "replace"), desc)
    if desc.startswith("/dev/pts/") or desc.startswith("/dev/tty"):
        return "terminal"
    if desc.startswith("pipe:"):
        return "pipe between the tool's own processes"
    if desc.startswith("TCP:[127.0.0.1:") or desc.startswith("TCP:[[::1]:"):
        return "TCP on loopback (127.0.0.1)"
    if desc.startswith(("TCP:", "UDP:", "TCPv6:", "UDPv6:")):
        return "NETWORK " + desc
    if desc.startswith("/dev/null"):
        return "/dev/null"
    if desc.startswith(tmpdir):
        return "file in the temporary node folder: " + re.sub(r"tn-cold-[^/]+", "tn-cold-XXXX", desc[len(tmpdir):])
    if desc.startswith(kit):
        return "file in the tool folder: " + desc[len(kit):]
    return "other: " + desc


def analyse(tracefile, secrets, kit, tmpdir, out, made_words=True):
    prog = {}                      # pid -> program name
    parent_prog = "strace-child"
    execs, opens, sockets, addrs, hits, rnd, rnd32 = [], {}, {}, {}, {}, [], []
    dgram, lookups, lookups_ok, sent_outside = set(), 0, 0, 0
    truncated = 0
    for line in open(tracefile, errors="replace"):
        m = HEAD.match(line)
        if not m:
            continue
        pid, call = m.group(1), m.group(2)
        if pid not in prog:
            prog[pid] = parent_prog
        strings = STR.findall(line)
        truncated += sum(1 for _, dots in strings if dots)
        if call in ("execve", "execveat") and "resumed" not in line.split("(")[0]:
            if not strings:
                continue
            parts = [unhex(s).decode("utf-8", "replace") for s, _ in strings]
            # argv is the first bracket group, env the second
            m2 = re.search(r"\((?:\d+<[^>]*>, )?\"[^\"]*\", \[(.*?)\], \[(.*)\]\)?", line)
            argv = [unhex(s).decode("utf-8", "replace") for s, _ in STR.findall(m2.group(1))] if m2 else parts[1:]
            envp = [unhex(s).decode("utf-8", "replace") for s, _ in STR.findall(m2.group(2))] if m2 else []
            ok = re.search(r"= 0\s*$", line) is not None or "<unfinished" in line
            if ok:
                prog[pid] = os.path.basename(parts[0])
                execs.append((prog[pid], argv, envp))
                parent_prog = prog[pid]
            continue
        who = prog[pid]
        if call in ("open", "openat", "openat2", "creat"):
            if re.search(r"O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND", line) or call == "creat":
                if strings and "= -1" not in line:
                    path = unhex(strings[0][0]).decode("utf-8", "replace")
                    opens.setdefault(who, set()).add(target_class(path, kit, tmpdir))
        elif call == "socket":
            m2 = re.search(r"socket\((\w+), ([\w|]+)", line)
            if m2:
                key = "%s %s" % (m2.group(1), m2.group(2).replace("|SOCK_CLOEXEC", "").replace("|SOCK_NONBLOCK", ""))
                sockets.setdefault(who, {}).setdefault(key, 0)
                sockets[who][key] += 1
                m3 = re.search(r"= (\d+)", line)
                if m3 and "SOCK_DGRAM" in key and key.startswith(("AF_INET ", "AF_INET6 ")):
                    dgram.add((pid, m3.group(1)))
        elif call in ("connect", "bind"):
            m2 = re.search(r"sa_family=(\w+)(?:, sin6?_port=htons\((\d+)\))?(?:, sin_addr=inet_addr\(\"([^\"]*)\"\))?"
                           r"(?:, sun_path=\"([^\"]*)\")?", line)
            if m2:
                fam = m2.group(1)
                ip = unhex(m2.group(3)).decode() if m2.group(3) else ""
                sun = unhex(m2.group(4)).decode("utf-8", "replace") if m2.group(4) else ""
                if fam == "AF_INET6":
                    m3 = re.search(r'inet_pton\(AF_INET6, "([^"]*)"', line)
                    ip = unhex(m3.group(1)).decode() if m3 else "?"
                where = ("%s %s:%s" % (fam, ip, "PORT" if m2.group(2) not in (None, "0") else "0")) if fam != "AF_UNIX" \
                    else "AF_UNIX " + sun
                if fam == "AF_NETLINK":
                    where = "AF_NETLINK (kernel interface list)"
                fdm = re.match(r"^\d+\s+connect\((\d+)", line)
                if call == "connect" and fdm and (pid, fdm.group(1)) in dgram:
                    lookups += 1                       # a route look-up: connect() on a datagram socket sends nothing
                    lookups_ok += 1 if re.search(r"= 0\s*$", line) else 0
                    continue
                addrs.setdefault(who, {}).setdefault("%s to %s" % (call, where), 0)
                addrs[who]["%s to %s" % (call, where)] += 1
        elif call == "getrandom":
            m2 = re.search(r", (\d+), (\w+|0)\) = (\d+)", line)
            if m2 and who.startswith("python"):
                rnd.append(int(m2.group(3)))
                if int(m2.group(3)) == 32 and strings:
                    rnd32.append(unhex(strings[0][0]))
        if call in ("write", "writev", "pwrite64", "pwritev", "pwritev2", "sendto", "sendmsg", "sendmmsg"):
            payload = b"".join(unhex(s) for s, _ in strings)
            fm = FD.match(line)
            tgt = target_class(fm.group(2), kit, tmpdir) if fm else "?"
            if tgt.startswith("NETWORK"):          # strace names the socket behind every descriptor (-yy)
                sent_outside += 1
            for name, needle in secrets.items():
                if needle in payload:
                    kind = re.sub(r" \(\d+\)$", "", name)
                    hits.setdefault((who, tgt), set()).add(kind)

    w = out.append
    w("A. Programs started (arguments shown with the folders shortened)")
    leak_arg = leak_env = 0
    for name, argv, envp in execs:
        shown = " ".join(argv).replace(kit, "KIT").replace(tmpdir, "TMP")
        shown = re.sub(r"tn-cold-\w+", "tn-cold-XXXX", shown)
        shown = re.sub(r"-rpcport=\d+", "-rpcport=PORT", shown)
        w("   %s" % shown[:400])
        blob_a, blob_e = "\0".join(argv).encode(), "\0".join(envp).encode()
        leak_arg += any(n in blob_a for n in secrets.values())
        leak_env += any(n in blob_e for n in secrets.values())
    w("   -> programs started: %d; with secret material in the arguments: %d; in the environment: %d"
      % (len(execs), leak_arg, leak_env))
    w("B. Files opened for writing or created, by program")
    for who in sorted(opens):
        for t in sorted(opens[who]):
            w("   %-14s %s" % (who, t))
    w("C. Writes that contain secret material, by program and destination")
    bad = 0
    for (who, tgt) in sorted(hits):
        allowed = tgt in ("terminal", "pipe between the tool's own processes", "TCP on loopback (127.0.0.1)")
        bad += not allowed
        w("   %-14s -> %-40s %s%s" % (who, tgt, "; ".join(sorted(hits[(who, tgt)]))[:230],
                                      "" if allowed else "   <== NOT EXPECTED"))
    w("   -> destinations other than terminal, pipe and loopback: %d" % bad)
    w("D. Sockets created, by program")
    for who in sorted(sockets):
        w("   %-14s %s" % (who, ", ".join("%s x%d" % kv for kv in sorted(sockets[who].items()))))
    w("   Addresses bound or connected to, by program")
    nonlocal_ = 0
    for who in sorted(addrs):
        for k, v in sorted(addrs[who].items()):
            nonlocal_ += not ("127.0.0.1" in k or "AF_UNIX" in k or "AF_NETLINK" in k or "::1" in k)
            w("   %-14s %s x%d" % (who, k, v))
    w("   -> bind/connect to anything but loopback, local sockets and the kernel: %d" % nonlocal_)
    w("   route look-ups for the offline check (connect on a datagram socket, which sends nothing): %d, of which the"
      % lookups)
    w("   kernel had a route for %d; writes or sends to any UDP socket or non-loopback TCP connection: %d"
      % (lookups_ok, sent_outside))
    w("   getrandom() calls by Python that returned exactly 32 bytes: %d (all sizes: %s)"
      % (sum(1 for r in rnd if r == 32), ",".join(str(r) for r in rnd)))
    if "entropy raw" in secrets and rnd32 and made_words:
        ent = secrets["entropy raw"]
        if "dice rolls" in secrets:
            mix = hashlib.sha256(secrets["dice rolls"]).digest()
            same = any(bytes(a ^ b for a, b in zip(r, mix)) == ent for r in rnd32)
            w("   the 24 words encode exactly (those 32 bytes from the system) XOR SHA-256(dice rolls): %s" % same)
        else:
            same = any(r == ent for r in rnd32)
            w("   the 24 words encode exactly those 32 bytes from the system: %s" % same)
    w("   strings cut short by strace (must be 0 for the search to be complete): %d" % truncated)
    return bad == 0 and nonlocal_ == 0 and leak_arg == 0 and leak_env == 0 and truncated == 0 and sent_outside == 0


def disk_search(secrets, roots, skip):
    found, scanned = [], 0
    strict = {k: v for k, v in secrets.items() if not k.startswith("numbered word")}
    for root in roots:
        for dirpath, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if os.path.join(dirpath, d) not in skip]
            for n in names:
                p = os.path.join(dirpath, n)
                if p in skip or os.path.islink(p) or not os.path.isfile(p):
                    continue
                try:
                    if os.path.getsize(p) > 300 << 20:
                        continue
                    data = open(p, "rb").read()
                except OSError:
                    continue
                scanned += 1
                for name, needle in strict.items():
                    if needle in data:
                        found.append((p, name))
                        break
    return scanned, found


def main():
    os.makedirs(WORK, exist_ok=True)
    kit = os.path.join(WORK, "kit-" + SCEN)
    tmpdir = os.path.join(WORK, "tmp-" + SCEN)
    home = os.path.join(WORK, "home-" + SCEN)
    for d in (kit, tmpdir, home):
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
    for name in ("cold-address.py", "tn-seed.py", "english.txt"):
        shutil.copy(os.path.join(SRC, name), kit)
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "TERM": "xterm-256color", "TN_BIN": BIN,
           "TMPDIR": tmpdir, "HOME": home, "LANG": "C.UTF-8"}
    chain = "regtest" if SCEN == "dry-regtest" else "main"
    args = {"dry-regtest": ["--dry-run", "--chain", "regtest"], "dry-main-dice": ["--dry-run", "--chain", "main", "--dice"],
            "real-netns": []}[SCEN]
    netns = SCEN == "real-netns"
    dice = "".join("123456"[(i * 5 + 1 + i // 7) % 6] for i in range(120)) if "--dice" in args else None
    out = []
    w = out.append
    w("Scenario: %s   (tool arguments: %s%s)" % (SCEN, " ".join(args) or "none, a real run",
                                                 "; inside a network namespace that has only the loopback interface"
                                                 if netns else ""))
    w("cold-address.py sha256 %s" % hashlib.sha256(open(os.path.join(kit, "cold-address.py"), "rb").read()).hexdigest())
    ok_all = True
    for step in ("new", "verify"):
        tracefile = os.path.join(WORK, "trace-%s-%s.txt" % (SCEN, step))
        if os.path.exists(tracefile):
            os.remove(tracefile)
        if step == "new":
            rc, words, s = run_new(kit, tracefile, args, netns, env, dice)
            secrets = needles(words, chain, dice)
        else:
            vargs = [a for a in args if a != "--dice"]
            rc, s = run_verify(kit, tracefile, vargs, netns, env, words)
        screen = ANSI.sub("", s.raw)
        w("")
        w("=== step '%s': exit code %d; trace has %d lines" % (step, rc, sum(1 for _ in open(tracefile))))
        if step == "new":
            said = [x for x in ("ok, the computer is offline", "ok, no network connection found") if x in screen]
            w("    the tool reported: %s" % (said[0] if said else "dry run (network check is informative only)"))
        else:
            w("    the tool reported: %s" % ("OK: the words on your paper give the saved address"
                                             if "OK: the words on your paper" in screen else "NOT OK"))
        ok = analyse(tracefile, secrets, kit, tmpdir, out, made_words=(step == "new")) and rc == 0
        ok_all = ok_all and ok
        left = sorted(os.listdir(tmpdir))
        w("E. Left in the temporary folder afterwards: %s" % (", ".join(left) if left else "nothing"))
        ok_all = ok_all and not left
    outdir = [d for d in os.listdir(kit) if d.startswith("out")]
    w("")
    w("Tool folder afterwards: %s" % ", ".join(sorted(os.listdir(kit))))
    for d in outdir:
        for n in sorted(os.listdir(os.path.join(kit, d))):
            w("   %s/%s  (%d bytes, mode %o)" % (d, n, os.path.getsize(os.path.join(kit, d, n)),
                                                 os.stat(os.path.join(kit, d, n)).st_mode & 0o777))
    roots = [kit, tmpdir, home, "/tmp", "/var/tmp", "/dev/shm", "/run", "/root"]
    skip = {os.path.join(WORK, "trace-%s-%s.txt" % (SCEN, st)) for st in ("new", "verify")}
    scanned, found = disk_search(secrets, [r for r in roots if os.path.isdir(r)], skip)
    w("Disk search for the phrase, any 3 words in a row, entropy, seed, keys and xprv (raw and hex) in")
    w("   %s: %d files read, %d contain secret material" % (", ".join(["KIT", "TMP", "HOME"] + roots[3:]),
                                                           scanned, len(found)))
    for p, name in found[:20]:
        w("   FOUND %s in %s" % (name, p))
    ok_all = ok_all and not found
    w("")
    w("RESULT %s" % ("OK" if ok_all else "CHECK"))
    print("\n".join(out))


if __name__ == "__main__":
    main()
