"""Single source of truth for the package version."""

__version__ = "0.1.0"

#: Upstream revisions this repository was written against, verified from official
#: documentation on 2026-10-22. Connectors cite these instead of inventing field names.
UPSTREAM_REFERENCES: dict[str, str] = {
    "cloudtrail_event_version": "1.11",
    "graph_api_version": "v1.0",
    "graph_signins_endpoint": "/auditLogs/signIns",
    "graph_directory_audits_endpoint": "/auditLogs/directoryAudits",
    "thehive_api_docs": "TheHive 5, POST /api/v1/alert",
}
