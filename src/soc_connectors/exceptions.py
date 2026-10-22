"""Exception taxonomy.

The distinction that matters to the pipeline is retryable (``TransientError``) versus not
retryable (``PermanentError``): it decides whether an event is retried with backoff or
dead-lettered immediately. Connectors and forwarders raise these instead of bare
``Exception`` so the runner can classify failures without guessing from a message.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from soc_connectors.types import RawEvent


class SocConnectorError(Exception):
    """Base class for every error this framework raises."""


class ConfigError(SocConnectorError):
    """Configuration is missing, malformed, inconsistent or references an unset variable."""


class CheckpointError(SocConnectorError):
    """The state file cannot be read, written or parsed."""


class MalformedEventError(SocConnectorError):
    """A single record cannot be parsed or normalized.

    Carries the offending ``RawEvent`` so the pipeline can dead-letter the payload
    (redacted) instead of losing the evidence of what failed.
    """

    def __init__(
        self, message: str, *, raw: RawEvent | None = None, field: str | None = None
    ) -> None:
        super().__init__(message)
        self.raw = raw
        self.field = field


class TransientError(SocConnectorError):
    """Attempt again: the condition is expected to clear (timeout, 5xx, 429, socket reset)."""


class PermanentError(SocConnectorError):
    """Do not attempt again: retrying cannot fix it (4xx other than 429, bad credentials,
    mapping rejection). The event goes to the dead-letter file."""


class PaginationError(SocConnectorError):
    """A source paged back to a cursor it had already returned — its paging contract is
    broken, and continuing would loop forever or silently re-read the same window."""


class AuthenticationError(PermanentError):
    """Credentials were rejected. Retrying would hammer the identity provider with a
    secret that does not work."""


class AuthorizationError(PermanentError):
    """Authenticated but not permitted — usually a missing API scope or IAM policy."""


class RateLimitedError(TransientError):
    """Upstream throttled us. ``retry_after_seconds`` comes from the response header when
    present, so the limiter defers to the server instead of guessing."""

    def __init__(self, message: str, *, retry_after_seconds: float | None = None) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class ForwardingError(SocConnectorError):
    """A destination failure that carries the destination id for the logs."""

    def __init__(self, message: str, *, forwarder_id: str, details: Any = None) -> None:
        super().__init__(message)
        self.forwarder_id = forwarder_id
        self.details = details


class PartialDeliveryError(ForwardingError):
    """The destination accepted the request but rejected individual items.

    Accepted items count as delivered; rejected items are dead-lettered with the
    destination's own reason, which is what turns an Elasticsearch mapping conflict into
    a diagnosable record instead of a silent drop.
    """

    def __init__(
        self,
        message: str,
        *,
        forwarder_id: str,
        accepted: int,
        rejected: list[dict[str, Any]],
        retryable_rejections: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(message, forwarder_id=forwarder_id, details=rejected)
        self.accepted = accepted
        self.rejected = rejected
        self.retryable_rejections = retryable_rejections or []
