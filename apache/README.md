# Apache profile

This is the local Apache/WordPress side of the three-profile runner.

The chain is:

```text
A1 session cleanup OOM
B1 stale session ID leak
A2 dangling session variables
B2 fake reference and fake HashTable
system("cat /flag >/out/local_flag")
```

The payload geometry and PHP 8.4.26 offsets come from the public `9bie/php2shell` research, commit `d6f888ebd3f0e188bb662e16f23747afdf35e42f`. I rewrote the small set of builders used here and kept fixed hashes for A1, B1 and A2.

`solve.py` is loopback-only and calibrated for the Docker profile in `lab/apache`. It pins 149 of the stock 150 prefork workers so all four exploit requests reach the same remaining child. The exploited child normally crashes after B2, but the flag copy completes first and Apache replaces the worker.

This is a local dummy-flag reproduction, not proof against an authentic HITCON instance.
