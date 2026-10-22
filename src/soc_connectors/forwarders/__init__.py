"""Destination forwarders.

Implemented in milestone M5. Each module subclasses ``BaseForwarder`` (added in M1) and
declares which exceptions are retryable, so a 429 from Elasticsearch and a permission
error from TheHive do not get the same retry policy.
"""
