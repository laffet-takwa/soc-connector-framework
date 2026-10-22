"""Cross-cutting primitives shared by every connector and forwarder.

Implemented in milestone M1: atomic checkpoint store, retry policy with exponential backoff
and jitter, dead-letter writer, cursor pagination helper, token-bucket rate limiter,
timestamp parsing and safe file I/O.
"""
