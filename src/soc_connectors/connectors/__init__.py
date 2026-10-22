"""Source connectors.

Implemented in milestones M2-M4. Each module subclasses ``BaseConnector`` (added in M1)
and implements ``fetch`` / ``parse`` / ``normalize``; pagination, checkpointing, retries
and dead-lettering stay in the pipeline so a new source does not reimplement them.
"""
