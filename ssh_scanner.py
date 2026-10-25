#!/usr/bin/env python3
"""
ssh_scanner.py
Checks SSH services for weak/legacy cryptographic configuration by grabbing
the server's unauthenticated SSH_MSG_KEXINIT (algorithm negotiation) packet
directly over a raw socket - no authentication, no paramiko/libssh needed.

Prompts for: targets file, port, export file, optional deny-list YAML.
After each pass, hosts that failed (timeout, refused, not SSH, unparseable
KEXINIT) can be retested on another TCP port (hosts that already succeeded
are skipped) until you choose to finish.
Exports a detailed per-target report plus a summary, and a CSV summary
written alongside the export file.

Targets file: one host/IP per line, '#' comments allowed. A line can carry
its own port (host:2222 or [ipv6]:2222); that port is used on the first pass
instead of the one you enter. Numbered lists ("1. host") are tolerated.

The identification exchange trick (echo the server's own version banner back
as our "client" ident to move it into KEXINIT) is inspired by evict/sshscan
(https://github.com/evict/sshscan). Differences from that tool:

  - Name-lists are parsed with the correct SSH wire format (uint32 length +
    raw bytes), so long modern lists (post-quantum KEX, cert host keys) aren't
    truncated at 256 bytes.
  - Algorithms are flagged against a deny-list of known-weak/legacy crypto, so
    new/unrecognized algorithms are not treated as findings by default.

Checks performed:
    - Protocol version (flags SSHv1 / SSHv1.99 compatibility mode)
    - Key exchange (KEX) algorithms offered
    - Host key algorithms offered
    - Symmetric ciphers offered (server->client)
    - MAC algorithms offered (server->client)
    - Compression algorithm offered (zlib - informational)
    - Terrapin (CVE-2023-48795) mitigation support (kex-strict marker)

No third-party packages needed (PyYAML only if you supply a deny-list YAML
with ciphers/macs/kex/hka lists).
"""

import csv
import os
import re
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

THREADS = 10     # concurrent connections per pass
TIMEOUT = 10.0   # seconds per connection
SSH_MSG_KEXINIT = 20
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"

# --------------------------------------------------------------------------
# Deny-lists: known-weak/legacy algorithms. Anything NOT on these lists is
# treated as acceptable (avoids false positives on new/modern algorithms).
# Override per list with a YAML file (keys: ciphers, macs, kex, hka).
# Entries ending in '-' are prefixes (GSS-API KEX families with OID suffixes).
# --------------------------------------------------------------------------

WEAK_KEX = [
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "gss-group1-sha1-",
    "gss-group14-sha1-",
    "gss-gex-sha1-",
    "rsa1024-sha1",
    "rsa2048-sha256",
]

WEAK_HOST_KEY = [
    "ssh-dss",
    "ssh-dss-cert-v01@openssh.com",
    "ssh-dss-cert-v00@openssh.com",
    "ssh-rsa",  # SHA-1 based signature scheme; deprecated by OpenSSH upstream
    "ssh-rsa-cert-v01@openssh.com",
    "ssh-rsa-cert-v00@openssh.com",
    "x509v3-sign-rsa",
    "x509v3-sign-dss",
]

WEAK_CIPHERS = [
    "none", "des-cbc", "3des-cbc", "3des-ctr", "blowfish-cbc", "cast128-cbc",
    "arcfour", "arcfour128", "arcfour256",
    "aes128-cbc", "aes192-cbc", "aes256-cbc", "rijndael-cbc@lysator.liu.se",
    "twofish-cbc", "twofish128-cbc", "twofish192-cbc", "twofish256-cbc",
    "serpent128-cbc", "serpent192-cbc", "serpent256-cbc",
    "idea-cbc", "seed-cbc@ssh.com",
]

WEAK_MACS = [
    "none",
    "hmac-md5", "hmac-md5-96", "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com",
    "hmac-sha1", "hmac-sha1-96", "hmac-sha1-96-etm@openssh.com",
    "hmac-ripemd160", "hmac-ripemd160@openssh.com", "hmac-ripemd160-etm@openssh.com",
    "umac-64", "umac-64-etm@openssh.com",
]

# Protocol-negotiation markers in the KEX list that aren't real KEX algorithms.
KEX_INFO_MARKERS = {
    "ext-info-c",
    "ext-info-s",
    "kex-strict-c-v00@openssh.com",
    "kex-strict-s-v00@openssh.com",
}

ALGO_LABELS = {"kex": "KEX", "host_key": "Host key", "ciphers": "Ciphers", "macs": "MACs"}


# ---------------------------------------------------------------- input helpers

def clean_path(p):
    """Strip whitespace/quotes, expand ~ and env vars."""
    p = p.strip().strip("'\"")
    return os.path.abspath(os.path.expandvars(os.path.expanduser(p))) if p else ""


def enable_tab_completion():
    try:
        import glob
        import readline

        def complete(text, state):
            matches = glob.glob(os.path.expanduser(text) + "*")
            matches = [m + "/" if os.path.isdir(m) else m for m in matches]
            return matches[state] if state < len(matches) else None

        readline.set_completer_delims(" \t\n;")
        readline.parse_and_bind("tab: complete")
        readline.set_completer(complete)
    except ImportError:
        pass


def progress_bar(done, total, current="", width=40):
    pct = done / total if total else 1
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    label = (current[:45] + "…") if len(current) > 46 else current
    sys.stdout.write(f"\r{CYAN}[{bar}]{RESET} {done}/{total} ({pct:6.1%})  {label:<47}")
    sys.stdout.flush()


# ---------------------------------------------------------------- deny-lists

def load_denylists(config_path):
    denylists = {"ciphers": WEAK_CIPHERS, "macs": WEAK_MACS, "kex": WEAK_KEX, "hka": WEAK_HOST_KEY}
    if not config_path:
        return denylists
    try:
        from yaml import safe_load
    except ImportError:
        print(f"{RED}[!] A deny-list YAML needs PyYAML: pip install pyyaml --break-system-packages{RESET}")
        sys.exit(1)
    with open(config_path) as fd:
        custom = safe_load(fd) or {}
    for key in denylists:
        if key in custom:
            denylists[key] = custom[key]
    return denylists


def find_weak(detected, deny_list):
    """Return items in `detected` that match an entry in `deny_list`."""
    deny_exact = {d.lower() for d in deny_list if not d.endswith("-")}
    deny_prefix = [d.lower() for d in deny_list if d.endswith("-")]
    return [item for item in detected
            if item.lower() in deny_exact or any(item.lower().startswith(p) for p in deny_prefix)]


# ---------------------------------------------------------------- targets

def parse_target(raw_target):
    """
    Parse "host", "host:port" or "[ipv6]:port" (scheme/path stripped).
    Returns (host, port_or_None).
    """
    target = SCHEME_RE.sub("", raw_target.strip()).split("/")[0]
    if target.startswith("["):
        m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", target)
        if m:
            return m.group(1), int(m.group(2)) if m.group(2) else None
        return target, None
    if target.count(":") == 1:
        host, _, port_str = target.partition(":")
        if port_str.isdigit():
            return host, int(port_str)
    return target, None


def load_targets(path):
    targets = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # strip list numbering ("1. host", "2)\thost") only when followed by whitespace,
            # so IPs like 192.0.2.72 are left intact
            line = re.sub(r"^\d+[.)]\s+", "", line).split()[0]
            if line not in targets:
                targets.append(line)
    return targets


# ---------------------------------------------------------------- SSH protocol

def read_name_list(buf, offset):
    """Read one SSH name-list (uint32 length + comma-separated names)."""
    length = struct.unpack_from("!I", buf, offset)[0]
    offset += 4
    raw = buf[offset:offset + length]
    if len(raw) < length:
        raise ValueError("name-list runs past end of packet")
    names = raw.decode("utf-8", errors="replace").split(",") if raw else []
    return names, offset + length


def unpack_msg_kex_init(kex):
    """
    Parse an SSH_MSG_KEXINIT packet:
        uint32 packet_length, byte padding_length, byte SSH_MSG_KEXINIT (20),
        byte[16] cookie, then name-lists: kex, host key, enc c2s, enc s2c,
        mac c2s, mac s2c, comp c2s, comp s2c, ...
    """
    if len(kex) < 22:
        raise ValueError("packet too short to be a valid SSH_MSG_KEXINIT")
    if kex[5] != SSH_MSG_KEXINIT:
        raise ValueError(f"did not receive SSH_MSG_KEXINIT (got message type {kex[5]})")

    offset = 22  # 4 (length) + 1 (padding_length) + 1 (message type) + 16 (cookie)
    kex_algos, offset = read_name_list(kex, offset)
    host_key_algos, offset = read_name_list(kex, offset)
    _enc_c2s, offset = read_name_list(kex, offset)
    enc_s2c, offset = read_name_list(kex, offset)
    _mac_c2s, offset = read_name_list(kex, offset)
    mac_s2c, offset = read_name_list(kex, offset)
    _cmp_c2s, offset = read_name_list(kex, offset)
    cmp_s2c, offset = read_name_list(kex, offset)
    return kex_algos, host_key_algos, enc_s2c, mac_s2c, cmp_s2c


def retrieve_kexinit(host, port):
    """
    Minimal SSH identification exchange. Returns (kex_init_bytes, version_line).
    Reads the server's ident line (skipping any pre-banner lines), keeps any
    bytes that arrived after it as the start of the KEXINIT packet, echoes the
    ident back, then reads the full length-prefixed packet.
    """
    with socket.create_connection((host, port), timeout=TIMEOUT) as s:
        buf = b""
        version = None
        first_line = None  # first non-SSH line, shown in the error if this isn't SSH
        while version is None:
            while b"\n" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    seen = first_line if first_line is not None else buf
                    raise ConnectionError("not SSH - connection closed without an SSH banner"
                                          + (f" (got: {seen[:60].decode('utf-8', 'replace')!r})"
                                             if seen.strip() else ""))
                buf += chunk
                if len(buf) > 16384:
                    raise ValueError("not SSH - no SSH banner in first 16 KB")
            line, buf = buf.split(b"\n", 1)
            if line.startswith(b"SSH-"):
                version = line.rstrip(b"\r")
            elif len(line) > 1024:
                raise ValueError("not SSH - oversized pre-banner line")
            elif first_line is None:
                first_line = line.rstrip(b"\r")

        # Echo the server's own (RFC4253-valid) ident back as our client ident.
        s.sendall(version + b"\r\n")

        while len(buf) < 4:
            chunk = s.recv(8192)
            if not chunk:
                raise ConnectionError("connection closed before SSH_MSG_KEXINIT was received")
            buf += chunk
        total_needed = struct.unpack("!I", buf[:4])[0] + 4
        if total_needed > 256 * 1024:
            raise ValueError("declared packet length is implausibly large - not SSH?")
        while len(buf) < total_needed:
            chunk = s.recv(8192)
            if not chunk:
                break
            buf += chunk
        return buf[:total_needed], version.decode("utf-8", errors="replace")


def check_protocol_version(v):
    if v.startswith("SSH-1.99"):
        return "WEAK", f"'{v}' - SSHv1/v2 compatibility mode; disable SSHv1 support entirely"
    if v.startswith("SSH-1"):
        return "FAIL", f"'{v}' - SSHv1 protocol in use; SSHv1 has known cryptographic weaknesses"
    if not v.startswith("SSH-2"):
        return "WEAK", f"'{v}' - unrecognized/non-standard protocol identification string"
    return "PASS", f"'{v}' - SSHv2"


def scan_target(host, port, denylists):
    """Returns a result dict. status is OK, FINDINGS or ERROR."""
    base = {"host": host, "port": port}
    try:
        kex_raw, version = retrieve_kexinit(host, port)
    except socket.timeout:
        return {**base, "status": "ERROR", "error": f"timeout after {TIMEOUT:.0f}s"}
    except socket.gaierror as e:
        return {**base, "status": "ERROR", "error": f"DNS lookup failed: {e}"}
    except (ConnectionError, OSError, ValueError) as e:
        return {**base, "status": "ERROR", "error": str(e) or e.__class__.__name__}

    try:
        kex_list_raw, hka_list, cipher_list, mac_list, cmp_list = unpack_msg_kex_init(kex_raw)
    except (struct.error, ValueError, IndexError) as e:
        return {**base, "status": "ERROR", "version": version,
                "error": f"failed to parse SSH_MSG_KEXINIT: {e}"}

    kex_list = [k for k in kex_list_raw if k not in KEX_INFO_MARKERS]
    proto_status, proto_detail = check_protocol_version(version)
    algorithms = {}
    for key, detected, deny in (("kex", kex_list, denylists["kex"]),
                                ("host_key", hka_list, denylists["hka"]),
                                ("ciphers", cipher_list, denylists["ciphers"]),
                                ("macs", mac_list, denylists["macs"])):
        weak = find_weak(detected, deny)
        algorithms[key] = {"detected": detected, "weak": weak, "status": "WEAK" if weak else "PASS"}

    issue_count = sum(a["status"] != "PASS" for a in algorithms.values()) + (proto_status != "PASS")
    return {
        **base,
        "status": "FINDINGS" if issue_count else "OK",
        "error": "",
        "version": version,
        "protocol": {"status": proto_status, "detail": proto_detail},
        "algorithms": algorithms,
        "compression_enabled": any("zlib" in c for c in cmp_list if c),
        "terrapin_mitigated": any(m.startswith("kex-strict") for m in kex_list_raw),
        "issue_count": issue_count,
    }


# ---------------------------------------------------------------- output

def color_status(s):
    if s == "FINDINGS":
        return f"{RED}{s}{RESET}"
    if s == "OK":
        return f"{GREEN}{s}{RESET}"
    if s == "ERROR":
        return f"{YELLOW}{s}{RESET}"
    return s


def write_detail(out, target, r):
    out.write("-" * 80 + "\n")
    out.write(f"Target: {target} ({r['host']}:{r['port']})\n")
    if r["status"] == "ERROR":
        if r.get("version"):
            out.write(f"  SSH Version Banner: {r['version']}\n")
        out.write(f"  ERROR: {r['error']}\n")
    else:
        out.write(f"  SSH Version Banner: {r['version']}\n")
        out.write(f"  Protocol Version [{r['protocol']['status']}]: {r['protocol']['detail']}\n")
        out.write(f"  Terrapin (CVE-2023-48795) mitigation supported: {r['terrapin_mitigated']}\n\n")
        for key, info in r["algorithms"].items():
            out.write(f"  {ALGO_LABELS[key]} [{info['status']}]:\n")
            out.write(f"    Detected: {', '.join(info['detected'])}\n")
            if info["weak"]:
                out.write(f"    Weak:     {', '.join(info['weak'])}\n")
            out.write("\n")
        out.write(f"  Compression (zlib) offered: {r['compression_enabled']}\n")
    out.write(f"\n[RESULT] {r['host']}:{r['port']} -> {r['status']}"
              + (f" | {r['issue_count']} issue(s)" if r["status"] == "FINDINGS" else "")
              + (f" | {r['error']}" if r["status"] == "ERROR" else "") + "\n\n")
    out.flush()


def finding_lines(r):
    lines = []
    if r["protocol"]["status"] != "PASS":
        lines.append(f"Protocol [{r['protocol']['status']}]: {r['protocol']['detail']}")
    for key, info in r["algorithms"].items():
        if info["weak"]:
            lines.append(f"Weak {ALGO_LABELS[key]}: {', '.join(info['weak'])}")
    if r["compression_enabled"]:
        lines.append("Note: zlib compression offered (informational)")
    if not r["terrapin_mitigated"]:
        lines.append("Note: no kex-strict marker (Terrapin mitigation not advertised)")
    return lines


# ---------------------------------------------------------------- main

def main():
    enable_tab_completion()
    print(f"{BOLD}SSH Weak Configuration Scanner{RESET}\n")

    # --- targets file (full path) ---
    targets_file = clean_path(input("Targets file (full path): "))
    while not os.path.isfile(targets_file):
        targets_file = clean_path(input(f"{RED}Not found.{RESET} Targets file (full path): "))

    # --- port ---
    port = input("Port [22]: ").strip() or "22"
    while not (port.isdigit() and 1 <= int(port) <= 65535):
        port = input(f"{RED}Invalid.{RESET} Port [22]: ").strip() or "22"

    # --- export file (full path) ---
    default_out = os.path.join(os.path.dirname(targets_file),
                               f"ssh_scan_p{port}_{datetime.now():%Y-%m-%d_%H%M}.txt")
    export_file = clean_path(input(f"Export file (full path) [{default_out}]: ")) or default_out
    if os.path.isdir(export_file):
        export_file = os.path.join(export_file, os.path.basename(default_out))
    out_dir = os.path.dirname(export_file)
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)
        print(f"{YELLOW}[*] Created {out_dir}{RESET}")
    csv_file = os.path.splitext(export_file)[0] + ".csv"

    # --- optional deny-list override ---
    config = clean_path(input("Deny-list YAML (full path) [none - use built-in]: "))
    while config and not os.path.isfile(config):
        config = clean_path(input(f"{RED}Not found.{RESET} Deny-list YAML [none]: "))
    denylists = load_denylists(config)

    targets = load_targets(targets_file)
    if not targets:
        print(f"{RED}[!] No targets in file.{RESET}")
        sys.exit(1)

    print(f"\n[*] {len(targets)} targets | export -> {export_file}\n")

    parsed = {t: parse_target(t) for t in targets}
    results = {t: {"host": parsed[t][0], "port": "", "status": "ERROR", "error": "not scanned",
                   "ports_tried": []} for t in targets}
    pending = list(targets)
    first_pass = True
    start = time.time()

    with open(export_file, "w") as out:
        out.write(f"SSH Weak Configuration Scan - {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        out.write(f"Targets file: {targets_file}\n")
        out.write(f"Deny-list: {config or 'built-in'}\n")
        out.write("=" * 80 + "\n\n")

        while True:
            succeeded = run_pass(pending, port, first_pass, parsed, results, denylists, out)
            first_pass = False
            pending = [t for t in pending if results[t]["status"] == "ERROR"]

            print(f"[*] Port {port}: {succeeded} scanned OK, {len(pending)} failed")
            if not pending:
                print(f"{GREEN}[+] All hosts scanned.{RESET}\n")
                break

            print(f"\n{YELLOW}Failed so far ({len(pending)}):{RESET}")
            for t in pending:
                print(f"  {t}  (tried: {', '.join(results[t]['ports_tried'])}) - {results[t]['error']}")

            port = prompt_next_port(results, pending)
            if port is None:
                print()
                break

        write_summary(out, targets, results)

    write_csv(csv_file, targets, results)
    print_results(targets, results, time.time() - start, export_file, csv_file)


def run_pass(targets, port, first_pass, parsed, results, denylists, out):
    """Scan the given targets on one port (concurrently). Returns how many succeeded."""
    jobs = []
    for t in targets:
        host, own_port = parsed[t]
        # A port written in the targets file wins on the first pass only.
        jobs.append((t, host, own_port if (first_pass and own_port) else int(port)))

    label = f"port {port}" + (" (or per-target ports)" if any(p for _, p in parsed.values()) and first_pass else "")
    print(f"\n{BOLD}[*] Scanning {len(jobs)} host(s) on {label}{RESET}\n")
    out.write(f"### PASS: {label} | {len(jobs)} host(s) | {datetime.now():%H:%M:%S}\n\n")

    succeeded = done = 0
    progress_bar(0, len(jobs))
    with ThreadPoolExecutor(max_workers=THREADS) as pool:
        futures = {pool.submit(scan_target, host, p, denylists): (t, host, p) for t, host, p in jobs}
        for fut in as_completed(futures):
            t, host, p = futures[fut]
            try:
                r = fut.result()
            except Exception as e:  # never let one target kill the pass
                r = {"host": host, "port": p, "status": "ERROR", "error": f"unexpected error: {e}"}
            results[t]["ports_tried"].append(str(p))
            if r["status"] != "ERROR":
                succeeded += 1
            results[t].update(r)
            write_detail(out, t, r)
            done += 1
            progress_bar(done, len(jobs), f"{host}:{p}")
    print("\n")
    return succeeded


def prompt_next_port(results, pending):
    tried_by_all = set.intersection(*(set(results[t]["ports_tried"]) for t in pending))
    while True:
        ans = input("\nRetest these on another TCP port, or [q] to finish with current results: ").strip().lower()
        if ans in ("q", "quit", "exit", "n", "no", ""):
            if ans == "":
                continue
            return None
        if not (ans.isdigit() and 1 <= int(ans) <= 65535):
            print(f"{RED}Enter a port (1-65535) or q.{RESET}")
            continue
        if ans in tried_by_all:
            print(f"{YELLOW}Port {ans} was already tried on all of these. Pick another.{RESET}")
            continue
        return ans


def write_summary(out, targets, results):
    out.write("\nSUMMARY\n" + "=" * 80 + "\n")
    out.write(f"{'Target':<45} {'Port':<6} {'Status':<10} {'Issues':<7} Banner\n")
    for t in targets:
        r = results[t]
        issues = str(r.get("issue_count", "")) if r["status"] != "ERROR" else "--"
        out.write(f"{t:<45} {str(r['port']):<6} {r['status']:<10} {issues:<7} {r.get('version', '')}\n")
    found = [t for t in targets if results[t]["status"] == "FINDINGS"]
    if found:
        out.write("\nFindings:\n")
        for t in found:
            r = results[t]
            out.write(f"  {r['host']}:{r['port']}\n")
            for line in finding_lines(r):
                out.write(f"    {line}\n")
    failed = [t for t in targets if results[t]["status"] == "ERROR"]
    if failed:
        out.write("\nFailed on every port tried:\n")
        for t in failed:
            r = results[t]
            out.write(f"  {t} (tried: {', '.join(r['ports_tried'])}) - {r['error']}\n")


def write_csv(csv_file, targets, results):
    fields = ["target", "host", "port", "status", "issue_count", "version", "protocol_status",
              "weak_kex", "weak_host_key", "weak_ciphers", "weak_macs",
              "terrapin_mitigated", "compression_enabled", "error", "ports_tried"]
    with open(csv_file, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for t in targets:
            r = results[t]
            ok = r["status"] != "ERROR"
            algos = r.get("algorithms", {})
            w.writerow({
                "target": t, "host": r["host"], "port": r["port"], "status": r["status"],
                "issue_count": r.get("issue_count", "") if ok else "",
                "version": r.get("version", ""),
                "protocol_status": r["protocol"]["status"] if ok else "",
                "weak_kex": " ".join(algos.get("kex", {}).get("weak", [])),
                "weak_host_key": " ".join(algos.get(#!/usr/bin/env python3
"""
ssh_scanner.py
Checks SSH services for weak/legacy cryptographic configuration by grabbing
the server's unauthenticated SSH_MSG_KEXINIT (algorithm negotiation) packet
directly over a raw socket - no authentication, no paramiko/libssh needed.

Prompts for: targets file, port, export file, optional deny-list YAML.
After each pass, hosts that failed (timeout, refused, not SSH, unparseable
KEXINIT) can be retested on another TCP port (hosts that already succeeded
are skipped) until you choose to finish.
Exports a detailed per-target report plus a summary, and a CSV summary
written alongside the export file.

Targets file: one host/IP per line, '#' comments allowed. A line can carry
its own port (host:2222 or [ipv6]:2222); that port is used on the first pass
instead of the one you enter. Numbered lists ("1. host") are tolerated.

The identification exchange trick (echo the server's own version banner back
as our "client" ident to move it into KEXINIT) is inspired by evict/sshscan
(https://github.com/evict/sshscan). Differences from that tool:

  - Name-lists are parsed with the correct SSH wire format (uint32 length +
    raw bytes), so long modern lists (post-quantum KEX, cert host keys) aren't
    truncated at 256 bytes.
  - Algorithms are flagged against a deny-list of known-weak/legacy crypto, so
    new/unrecognized algorithms are not treated as findings by default.

Checks performed:
    - Protocol version (flags SSHv1 / SSHv1.99 compatibility mode)
    - Key exchange (KEX) algorithms offered
    - Host key algorithms offered
    - Symmetric ciphers offered (server->client)
    - MAC algorithms offered (server->client)
    - Compression algorithm offered (zlib - informational)
    - Terrapin (CVE-2023-48795) mitigation support (kex-strict marker)

No third-party packages needed (PyYAML only if you supply a deny-list YAML
with ciphers/macs/kex/hka lists).
"""

import csv
import os
import re
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

THREADS = 10     # concurrent connections per pass
TIMEOUT = 10.0   # seconds per connection
SSH_MSG_KEXINIT = 20
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"

# --------------------------------------------------------------------------
# Deny-lists: known-weak/legacy algorithms. Anything NOT on these lists is
# treated as acceptable (avoids false positives on new/modern algorithms).
# Override per list with a YAML file (keys: ciphers, macs, kex, hka).
# Entries ending in '-' are prefixes (GSS-API KEX families with OID suffixes).
# --------------------------------------------------------------------------

WEAK_KEX = [
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "gss-group1-sha1-",
    "gss-group14-sha1-",
    "gss-gex-sha1-",
    "rsa1024-sha1",
    "rsa2048-sha256",
]

WEAK_HOST_KEY = [
    "ssh-dss",
    "ssh-dss-cert-v01@openssh.com",
    "ssh-dss-cert-v00@openssh.com",
    "ssh-rsa",  # SHA-1 based signature scheme; deprecated by OpenSSH upstream
    "ssh-rsa-cert-v01@openssh.com",
    "ssh-rsa-cert-v00@openssh.com",
    "x509v3-sign-rsa",
    "x509v3-sign-dss",
]

WEAK_CIPHERS = [
    "none", "des-cbc", "3des-cbc", "3des-ctr", "blowfish-cbc", "cast128-cbc",
    "arcfour", "arcfour128", "arcfour256",
    "aes128-cbc", "aes192-cbc", "aes256-cbc", "rijndael-cbc@lysator.liu.se",
    "twofish-cbc", "twofish128-cbc", "twofish192-cbc", "twofish256-cbc",
    "serpent128-cbc", "serpent192-cbc", "serpent256-cbc",
    "idea-cbc", "seed-cbc@ssh.com",
]

WEAK_MACS = [
    "none",
    "hmac-md5", "hmac-md5-96", "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com",
    "hmac-sha1", "hmac-sha1-96", "hmac-sha1-96-etm@openssh.com",
    "hmac-ripemd160", "hmac-ripemd160@openssh.com", "hmac-ripemd160-etm@openssh.com",
    "umac-64", "umac-64-etm@openssh.com",
]

# Protocol-negotiation markers in the KEX list that aren't real KEX algorithms.
KEX_INFO_MARKERS = {
    "ext-info-c",
    "ext-info-s",
    "kex-strict-c-v00@openssh.com",
    "kex-strict-s-v00@openssh.com",
}

ALGO_LABELS = {"kex": "KEX", "host_key": "Host key", "ciphers": "Ciphers", "macs": "MACs"}


# ---------------------------------------------------------------- input helpers

def clean_path(p):
    """Strip whitespace/quotes, expand ~ and env vars."""
    p = p.strip().strip("'\"")
    return os.path.abspath(os.path.expandvars(os.path.expanduser(p))) if p else ""


def enable_tab_completion():
    try:
        import glob
        import readline

        def complete(text, state):
            matches = glob.glob(os.path.expanduser(text) + "*")
            matches = [m + "/" if os.path.isdir(m) else m for m in matches]
            return matches[state] if state < len(matches) else None

        readline.set_completer_delims(" \t\n;")
        readline.parse_and_bind("tab: complete")
        readline.set_completer(complete)
    except ImportError:
        pass


def progress_bar(done, total, current="", width=40):
    pct = done / total if total else 1
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    label = (current[:45] + "…") if len(current) > 46 else current
    sys.stdout.write(f"\r{CYAN}[{bar}]{RESET} {done}/{total} ({pct:6.1%})  {label:<47}")
    sys.stdout.flush()


# ---------------------------------------------------------------- deny-lists

def load_denylists(config_path):
    denylists = {"ciphers": WEAK_CIPHERS, "macs": WEAK_MACS, "kex": WEAK_KEX, "hka": WEAK_HOST_KEY}
    if not config_path:
        return denylists
    try:
        from yaml import safe_load
    except ImportError:
        print(f"{RED}[!] A deny-list YAML needs PyYAML: pip install pyyaml --break-system-packages{RESET}")
        sys.exit(1)
    with open(config_path) as fd:
        custom = safe_load(fd) or {}
    for key in denylists:
        if key in custom:
            denylists[key] = custom[key]
    return denylists


def find_weak(detected, deny_list):
    """Return items in `detected` that match an entry in `deny_list`."""
    deny_exact = {d.lower() for d in deny_list if not d.endswith("-")}
    deny_prefix = [d.lower() for d in deny_list if d.endswith("-")]
    return [item for item in detected
            if item.lower() in deny_exact or any(item.lower().startswith(p) for p in deny_prefix)]


# ---------------------------------------------------------------- targets

def parse_target(raw_target):
    """
    Parse "host", "host:port" or "[ipv6]:port" (scheme/path stripped).
    Returns (host, port_or_None).
    """
    target = SCHEME_RE.sub("", raw_target.strip()).split("/")[0]
    if target.startswith("["):
        m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", target)
        if m:
            return m.group(1), int(m.group(2)) if m.group(2) else None
        return target, None
    if target.count(":") == 1:
        host, _, port_str = target.partition(":")
        if port_str.isdigit():
            return host, int(port_str)
    return target, None


def load_targets(path):
    targets = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # strip list numbering ("1. host", "2)\thost") only when followed by whitespace,
            # so IPs like 192.0.2.72 are left intact
            line = re.sub(r"^\d+[.)]\s+", "", line).split()[0]
            if line not in targets:
                targets.append(line)
    return targets


# ---------------------------------------------------------------- SSH protocol

def read_name_list(buf, offset):
    """Read one SSH name-list (uint32 length + comma-separated names)."""
    length = struct.unpack_from("!I", buf, offset)[0]
    offset += 4
    raw = buf[offset:offset + length]
    if len(raw) < length:
        raise ValueError("name-list runs past end of packet")
    names = raw.decode("utf-8", errors="replace").split(",") if raw else []
    return names, offset + length


def unpack_msg_kex_init(kex):
    """
    Parse an SSH_MSG_KEXINIT packet:
        uint32 packet_length, byte padding_length, byte SSH_MSG_KEXINIT (20),
        byte[16] cookie, then name-lists: kex, host key, enc c2s, enc s2c,
        mac c2s, mac s2c, comp c2s, comp s2c, ...
    """
    if len(kex) < 22:
        raise ValueError("packet too short to be a valid SSH_MSG_KEXINIT")
    if kex[5] != SSH_MSG_KEXINIT:
        raise ValueError(f"did not receive SSH_MSG_KEXINIT (got message type {kex[5]})")

    offset = 22  # 4 (length) + 1 (padding_length) + 1 (message type) + 16 (cookie)
    kex_algos, offset = read_name_list(kex, offset)
    host_key_algos, offset = read_name_list(kex, offset)
    _enc_c2s, offset = read_name_list(kex, offset)
    enc_s2c, offset = read_name_list(kex, offset)
    _mac_c2s, offset = read_name_list(kex, offset)
    mac_s2c, offset = read_name_list(kex, offset)
    _cmp_c2s, offset = read_name_list(kex, offset)
    cmp_s2c, offset = read_name_list(kex, offset)
    return kex_algos, host_key_algos, enc_s2c, mac_s2c, cmp_s2c


def retrieve_kexinit(host, port):
    """
    Minimal SSH identification exchange. Returns (kex_init_bytes, version_line).
    Reads the server's ident line (skipping any pre-banner lines), keeps any
    bytes that arrived after it as the start of the KEXINIT packet, echoes the
    ident back, then reads the full length-prefixed packet.
    """
    with socket.create_connection((host, port), timeout=TIMEOUT) as s:
        buf = b""
        version = None
        first_line = None  # first non-SSH line, shown in the error if this isn't SSH
        while version is None:
            while b"\n" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    seen = first_line if first_line is not None else buf
                    raise ConnectionError("not SSH - connection closed without an SSH banner"
                                          + (f" (got: {seen[:60].decode('utf-8', 'replace')!r})"
                                             if seen.strip() else ""))
                buf += chunk
                if len(buf) > 16384:
                    raise ValueError("not SSH - no SSH banner in first 16 KB")
            line, buf = buf.split(b"\n", 1)
            if line.startswith(b"SSH-"):
                version = line.rstrip(b"\r")
            elif len(line) > 1024:
                raise ValueError("not SSH - oversized pre-banner line")
            elif first_line is None:
                first_line = line.rstrip(b"\r")

        # Echo the server's own (RFC4253-valid) ident back as our client ident.
        s.sendall(version + b"\r\n")

        while len(buf) < 4:
            chunk = s.recv(8192)
            if not chunk:
                raise ConnectionError("connection closed before SSH_MSG_KEXINIT was received")
            buf += chunk
        total_needed = struct.unpack("!I", buf[:4])[0] + 4
        if total_needed > 256 * 1024:
            raise ValueError("declared packet length is implausibly large - not SSH?")
        while len(buf) < total_needed:
            chunk = s.recv(8192)
            if not chunk:
                break
            buf += chunk
        return buf[:total_needed], version.decode("utf-8", errors="replace")


def check_protocol_version(v):
    if v.startswith("SSH-1.99"):
        return "WEAK", f"'{v}' - SSHv1/v2 compatibility mode; disable SSHv1 support entirely"
    if v.startswith("SSH-1"):
        return "FAIL", f"'{v}' - SSHv1 protocol in use; SSHv1 has known cryptographic weaknesses"
    if not v.startswith("SSH-2"):
        return "WEAK", f"'{v}' - unrecognized/non-standard protocol identification string"
    return "PASS", f"'{v}' - SSHv2"


def scan_target(host, port, denylists):
    """Returns a result dict. status is OK, FINDINGS or ERROR."""
    base = {"host": host, "port": port}
    try:
        kex_raw, version = retrieve_kexinit(host, port)
    except socket.timeout:
        return {**base, "status": "ERROR", "error": f"timeout after {TIMEOUT:.0f}s"}
    except socket.gaierror as e:
        return {**base, "status": "ERROR", "error": f"DNS lookup failed: {e}"}
    except (ConnectionError, OSError, ValueError) as e:
        return {**base, "status": "ERROR", "error": str(e) or e.__class__.__name__}

    try:
        kex_list_raw, hka_list, cipher_list, mac_list, cmp_list = unpack_msg_kex_init(kex_raw)
    except (struct.error, ValueError, IndexError) as e:
        return {**base, "status": "ERROR", "version": version,
                "error": f"failed to parse SSH_MSG_KEXINIT: {e}"}

    kex_list = [k for k in kex_list_raw if k not in KEX_INFO_MARKERS]
    proto_status, proto_detail = check_protocol_version(version)
    algorithms = {}
    for key, detected, deny in (("kex", kex_list, denylists["kex"]),
                                ("host_key", hka_list, denylists["hka"]),
                                ("ciphers", cipher_list, denylists["ciphers"]),
                                ("macs", mac_list, denylists["macs"])):
        weak = find_weak(detected, deny)
        algorithms[key] = {"detected": detected, "weak": weak, "status": "WEAK" if weak else "PASS"}

    issue_count = sum(a["status"] != "PASS" for a in algorithms.values()) + (proto_status != "PASS")
    return {
        **base,
        "status": "FINDINGS" if issue_count else "OK",
        "error": "",
        "version": version,
        "protocol": {"status": proto_status, "detail": proto_detail},
        "algorithms": algorithms,
        "compression_enabled": any("zlib" in c for c in cmp_list if c),
        "terrapin_mitigated": any(m.startswith("kex-strict") for m in kex_list_raw),
        "issue_count": issue_count,
    }


# ---------------------------------------------------------------- output

def color_status(s):
    if s == "FINDINGS":
        return f"{RED}{s}{RESET}"
    if s == "OK":
        return f"{GREEN}{s}{RESET}"
    if s == "ERROR":
        return f"{YELLOW}{s}{RESET}"
    return s


def write_detail(out, target, r):
    out.write("-" * 80 + "\n")
    out.write(f"Target: {target} ({r['host']}:{r['port']})\n")
    if r["status"] == "ERROR":
        if r.get("version"):
            out.write(f"  SSH Version Banner: {r['version']}\n")
        out.write(f"  ERROR: {r['error']}\n")
    else:
        out.write(f"  SSH Version Banner: {r['version']}\n")
        out.write(f"  Protocol Version [{r['protocol']['status']}]: {r['protocol']['detail']}\n")
        out.write(f"  Terrapin (CVE-2023-48795) mitigation supported: {r['terrapin_mitigated']}\n\n")
        for key, info in r["algorithms"].items():
            out.write(f"  {ALGO_LABELS[key]} [{info['status']}]:\n")
            out.write(f"    Detected: {', '.join(info['detected'])}\n")
            if info["weak"]:
                out.write(f"    Weak:     {', '.join(info['weak'])}\n")
            out.write("\n")
        out.write(f"  Compression (zlib) offered: {r['compression_enabled']}\n")
    out.write(f"\n[RESULT] {r['host']}:{r['port']} -> {r['status']}"
              + (f" | {r['issue_count']} issue(s)" if r["status"] == "FINDINGS" else "")
              + (f" | {r['error']}" if r["status"] == "ERROR" else "") + "\n\n")
    out.flush()


def finding_lines(r):
    lines = []
    if r["protocol"]["status"] != "PASS":
        lines.append(f"Protocol [{r['protocol']['status']}]: {r['protocol']['detail']}")
    for key, info in r["algorithms"].items():
        if info["weak"]:
            lines.append(f"Weak {ALGO_LABELS[key]}: {', '.join(info['weak'])}")
    if r["compression_enabled"]:
        lines.append("Note: zlib compression offered (informational)")
    if not r["terrapin_mitigated"]:
        lines.append("Note: no kex-strict marker (Terrapin mitigation not advertised)")
    return lines


# ---------------------------------------------------------------- main

def main():
    enable_tab_completion()
    print(f"{BOLD}SSH Weak Configuration Scanner{RESET}\n")

    # --- targets file (full path) ---
    targets_file = clean_path(input("Targets file (full path): "))
    while not os.path.isfile(targets_file):
        targets_file = clean_path(input(f"{RED}Not found.{RESET} Targets file (full path): "))

    # --- port ---
    port = input("Port [22]: ").strip() or "22"
    while not (port.isdigit() and 1 <= int(port) <= 65535):
        port = input(f"{RED}Invalid.{RESET} Port [22]: ").strip() or "22"

    # --- export file (full path) ---
    default_out = os.path.join(os.path.dirname(targets_file),
                               f"ssh_scan_p{port}_{datetime.now():%Y-%m-%d_%H%M}.txt")
    export_file = clean_path(input(f"Export file (full path) [{default_out}]: ")) or default_out
    if os.path.isdir(export_file):
        export_file = os.path.join(export_file, os.path.basename(default_out))
    out_dir = os.path.dirname(export_file)
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)
        print(f"{YELLOW}[*] Created {out_dir}{RESET}")
    csv_file = os.path.splitext(export_file)[0] + ".csv"

    # --- optional deny-list override ---
    config = clean_path(input("Deny-list YAML (full path) [none - use built-in]: "))
    while config and not os.path.isfile(config):
        config = clean_path(input(f"{RED}Not found.{RESET} Deny-list YAML [none]: "))
    denylists = load_denylists(config)

    targets = load_targets(targets_file)
    if not targets:
        print(f"{RED}[!] No targets in file.{RESET}")
        sys.exit(1)

    print(f"\n[*] {len(targets)} targets | export -> {export_file}\n")

    parsed = {t: parse_target(t) for t in targets}
    results = {t: {"host": parsed[t][0], "port": "", "status": "ERROR", "error": "not scanned",
                   "ports_tried": []} for t in targets}
    pending = list(targets)
    first_pass = True
    start = time.time()

    with open(export_file, "w") as out:
        out.write(f"SSH Weak Configuration Scan - {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        out.write(f"Targets file: {targets_file}\n")
        out.write(f"Deny-list: {config or 'built-in'}\n")
        out.write("=" * 80 + "\n\n")

        while True:
            succeeded = run_pass(pending, port, first_pass, parsed, results, denylists, out)
            first_pass = False
            pending = [t for t in pending if results[t]["status"] == "ERROR"]

            print(f"[*] Port {port}: {succeeded} scanned OK, {len(pending)} failed")
            if not pending:
                print(f"{GREEN}[+] All hosts scanned.{RESET}\n")
                break

            print(f"\n{YELLOW}Failed so far ({len(pending)}):{RESET}")
            for t in pending:
                print(f"  {t}  (tried: {', '.join(results[t]['ports_tried'])}) - {results[t]['error']}")

            port = prompt_next_port(results, pending)
            if port is None:
                print()
                break

        write_summary(out, targets, results)

    write_csv(csv_file, targets, results)
    print_results(targets, results, time.time() - start, export_file, csv_file)


def run_pass(targets, port, first_pass, parsed, results, denylists, out):
    """Scan the given targets on one port (concurrently). Returns how many succeeded."""
    jobs = []
    for t in targets:
        host, own_port = parsed[t]
        # A port written in the targets file wins on the first pass only.
        jobs.append((t, host, own_port if (first_pass and own_port) else int(port)))

    label = f"port {port}" + (" (or per-target ports)" if any(p for _, p in parsed.values()) and first_pass else "")
    print(f"\n{BOLD}[*] Scanning {len(jobs)} host(s) on {label}{RESET}\n")
    out.write(f"### PASS: {label} | {len(jobs)} host(s) | {datetime.now():%H:%M:%S}\n\n")

    succeeded = done = 0
    progress_bar(0, len(jobs))
    with ThreadPoolExecutor(max_workers=THREADS) as pool:
        futures = {pool.submit(scan_target, host, p, denylists): (t, host, p) for t, host, p in jobs}
        for fut in as_completed(futures):
            t, host, p = futures[fut]
            try:
                r = fut.result()
            except Exception as e:  # never let one target kill the pass
                r = {"host": host, "port": p, "status": "ERROR", "error": f"unexpected error: {e}"}
            results[t]["ports_tried"].append(str(p))
            if r["status"] != "ERROR":
                succeeded += 1
            results[t].update(r)
            write_detail(out, t, r)
            done += 1
            progress_bar(done, len(jobs), f"{host}:{p}")
    print("\n")
    return succeeded


def prompt_next_port(results, pending):
    tried_by_all = set.intersection(*(set(results[t]["ports_tried"]) for t in pending))
    while True:
        ans = input("\nRetest these on another TCP port, or [q] to finish with current results: ").strip().lower()
        if ans in ("q", "quit", "exit", "n", "no", ""):
            if ans == "":
                continue
            return None
        if not (ans.isdigit() and 1 <= int(ans) <= 65535):
            print(f"{RED}Enter a port (1-65535) or q.{RESET}")
            continue
        if ans in tried_by_all:
            print(f"{YELLOW}Port {ans} was already tried on all of these. Pick another.{RESET}")
            continue
        return ans


def write_summary(out, targets, results):
    out.write("\nSUMMARY\n" + "=" * 80 + "\n")
    out.write(f"{'Target':<45} {'Port':<6} {'Status':<10} {'Issues':<7} Banner\n")
    for t in targets:
        r = results[t]
        issues = str(r.get("issue_count", "")) if r["status"] != "ERROR" else "--"
        out.write(f"{t:<45} {str(r['port']):<6} {r['status']:<10} {issues:<7} {r.get('version', '')}\n")
    found = [t for t in targets if results[t]["status"] == "FINDINGS"]
    if found:
        out.write("\nFindings:\n")
        for t in found:
            r = results[t]
            out.write(f"  {r['host']}:{r['port']}\n")
            for line in finding_lines(r):
                out.write(f"    {line}\n")
    failed = [t for t in targets if results[t]["status"] == "ERROR"]
    if failed:
        out.write("\nFailed on every port tried:\n")
        for t in failed:
            r = results[t]
            out.write(f"  {t} (tried: {', '.join(r['ports_tried'])}) - {r['error']}\n")


def write_csv(csv_file, targets, results):
    fields = ["target", "host", "port", "status", "issue_count", "version", "protocol_status",
              "weak_kex", "weak_host_key", "weak_ciphers", "weak_macs",
              "terrapin_mitigated", "compression_enabled", "error", "ports_tried"]
    with open(csv_file, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for t in targets:
            r = results[t]
            ok = r["status"] != "ERROR"
            algos = r.get("algorithms", {})
            w.writerow({
                "target": t, "host": r["host"], "port": r["port"], "status": r["status"],
                "issue_count": r.get("issue_count", "") if ok else "",
                "version": r.get("version", ""),
                "protocol_status": r["protocol"]["status"] if ok else "",
                "weak_kex": " ".join(algos.get("kex", {}).get("weak", [])),
                "weak_host_key": " ".join(algos.get("host_key", {}).get("weak", [])),
                "weak_ciphers": " ".join(algos.get("ciphers", {}).get("weak", [])),
                "weak_macs": " ".join(algos.get("macs", {}).get("weak", [])),
                "terrapin_mitigated": r.get("terrapin_mitigated", "") if ok else "",
                "compression_enabled": r.get("compression_enabled", "") if ok else "",
                "error": r.get("error", ""),
                "ports_tried": " ".join(r["ports_tried"]),
            })


def print_results(targets, results, elapsed, export_file, csv_file):
    print(f"{BOLD}{'Target':<45} {'Port':<6} {'Status':<10} {'Issues':<7} Banner{RESET}")
    print("-" * 110)
    for t in targets:
        r = results[t]
        cs = color_status(r["status"])
        pad = 10 + (len(cs) - len(r["status"]))
        issues = str(r.get("issue_count", "")) if r["status"] != "ERROR" else "--"
        print(f"{t:<45} {str(r['port']):<6} {cs:<{pad}} {issues:<7} {r.get('version', '')}")
    print("-" * 110)

    found = [t for t in targets if results[t]["status"] == "FINDINGS"]
    failed = [t for t in targets if results[t]["status"] == "ERROR"]
    print(f"\n[*] {len(found)}/{len(targets)} targets with weak SSH configuration ({elapsed:.0f}s)")
    if found:
        print(f"\n{RED}Affected:{RESET}")
        for t in found:
            r = results[t]
            print(f"  {r['host']}:{r['port']}")
            for line in finding_lines(r):
                print(f"    {line}")
    if failed:
        print(f"\n{YELLOW}Failed on every port tried:{RESET}")
        for t in failed:
            r = results[t]
            print(f"  {t} (tried: {', '.join(r['ports_tried'])}) - {r['error']}")
    print(f"\n[+] Detailed report + summary: {export_file}")
    print(f"[+] CSV: {csv_file}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted.{RESET}")
        sys.exit(130)"host_key", {}).get("weak", [])),
                "weak_ciphers": " ".join(algos.get("ciphers", {}).get("weak", [])),
                "weak_macs": " ".join(algos.get("macs", {}).get("weak", [])),
                "terrapin_mitigated": r.get("terrapin_mitigated", "") if ok else "",
                "compression_enabled": r.get("compression_enabled", "") if ok else "",
                "error": r.get("error", ""),
                "ports_tried": " ".join(r["ports_tried"]),
            })


def print_results(targets, results, elapsed, export_file, csv_file):
    print(f"{BOLD}{'Target':<45} {'Port':<6} {'Status':<10} {'Issues':<7} Banner{RESET}")
    print("-" * 110)
    for t in targets:
        r = results[t]
        cs = color_status(r["status"])
        pad = 10 + (len(cs) - len(r["status"]))
        issues = str(r.get("issue_count", "")) if r["status"] != "ERROR" else "--"
        print(f"{t:<45} {str(r['port']):<6} {cs:<{pad}} {issues:<7} {r.get('version', '')}")
    print("-" * 110)

    found = [t for t in targets if results[t]["status"] == "FINDINGS"]
    failed = [t for t in targets if results[t]["status"] == "ERROR"]
    print(f"\n[*] {len(found)}/{len(targets)} targets with weak SSH configuration ({elapsed:.0f}s)")
    if found:
        print(f"\n{RED}Affected:{RESET}")
        for t in found:
            r = results[t]
            print(f"  {r['host']}:{r['port']}")
            for line in finding_lines(r):
                print(f"    {line}")
    if failed:
        print(f"\n{YELLOW}Failed on every port tried:{RESET}")
        for t in failed:
            r = results[t]
            print(f"  {t} (tried: {', '.join(r['ports_tried'])}) - {r['error']}")
    print(f"\n[+] Detailed report + summary: {export_file}")
    print(f"[+] CSV: {csv_file}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted.{RESET}")
        sys.exit(130)
