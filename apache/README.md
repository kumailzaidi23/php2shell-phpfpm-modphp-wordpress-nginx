# Apache profiles

This directory contains the common loopback-only runner and exact payload
builders for three Apache/WordPress profiles: PHP 8.3.35, 8.4.26 and 8.5.11.

The chain is:

```text
A1 session cleanup OOM
B1 stale session ID leak
A2 dangling session variables
B2 fake reference and fake HashTable
system("cat /flag >/out/local_flag")
```

The PHP 8.4.26 geometry starts from public `9bie/php2shell` research, commit
`d6f888ebd3f0e188bb662e16f23747afdf35e42f`. The PHP 8.3 and 8.5 builders use
separately measured stale-ID, symbol and final-stage layouts from the pinned
local WordPress clones. A1, B1 and A2 are rebuilt in memory and checked against
fixed byte counts and SHA-256 hashes before any request is sent.

`apache84` pins 149 of the stock 150 prefork workers. `apache83` and `apache85`
use single-worker labs. The exploited child normally crashes after B2, but the
flag copy completes first and Apache replaces it.

```bash
python3 apache/solve.py --profile apache83
python3 apache/solve.py --profile apache84
python3 apache/solve.py --profile apache85
```

These are local dummy-flag reproductions, not proof against an authentic
HITCON instance or an arbitrary build with the same PHP version string.
