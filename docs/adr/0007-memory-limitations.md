# ADR 0007: Memory Limitations

Do not claim secure memory wiping in CPython. Immutable strings, copies, and GC
timing make a reliable wipe promise dishonest. Minimize secret lifetime instead.
