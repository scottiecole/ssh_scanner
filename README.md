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
