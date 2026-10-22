"""Fan-out: one normalised event, many destinations, each with its own rules.

A firewall event is worth indexing in Elasticsearch, worth shipping to Wazuh, and — if it is
severe enough — worth turning into a TheHive alert. Each destination decides its own severity
floor and batch size, and each one's failure is independent: an Elasticsearch outage must not
stop the Wazuh file from being written, and neither may stop the others. Every refused item is
dead-lettered with the destination's own reason, because "forwarding failed" is not a
diagnosable sentence.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from functools import partial
from typing import Any

from soc_connectors.forwarders.base import BaseForwarder, DeliveryResult
from soc_connectors.metrics import Metrics
from soc_connectors.pipeline.batch import chunk
from soc_connectors.schema.ecs_models import EcsEvent, to_document
from soc_connectors.schema.redaction import RedactionSettings
from soc_connectors.utils.dead_letter import DeadLetterQueue
from soc_connectors.utils.retry import RetryPolicy, retry_call


@dataclass(slots=True)
class Route:
    """One destination's routing rules, resolved from validated config."""

    forwarder: BaseForwarder
    severity_min: int = 0
    batch_size: int = 200
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)


@dataclass(slots=True)
class DispatchReport:
    """Counts for one dispatch. Two different units, deliberately not merged.

    ``accepted``/``rejected``/``dead_lettered`` count *delivery records* — one event routed to
    two destinations is two records. ``events_delivered``/``events_failed`` count *events*, so
    a cycle report cannot be inflated by fan-out.
    """

    routed: int = 0
    accepted: int = 0
    rejected: int = 0
    dead_lettered: int = 0
    events_delivered: int = 0
    events_failed: int = 0
    errors: list[str] = field(default_factory=list)
    per_destination: dict[str, dict[str, int]] = field(default_factory=dict)

    def totals(self, destination: str) -> dict[str, int]:
        return self.per_destination.setdefault(
            destination, {"accepted": 0, "rejected": 0, "dead_lettered": 0, "skipped": 0}
        )

    @property
    def failed(self) -> bool:
        return bool(self.errors) or self.rejected > 0


class Dispatcher:
    """Sends events to every route that wants them."""

    def __init__(
        self,
        routes: Sequence[Route],
        *,
        metrics: Metrics,
        redaction: RedactionSettings | None = None,
        log: logging.Logger | None = None,
    ) -> None:
        self.routes = list(routes)
        self.metrics = metrics
        self.redaction = redaction
        self.log = log or logging.getLogger("soc_connectors.dispatcher")

    def dispatch(
        self,
        events: Sequence[EcsEvent],
        *,
        source_id: str,
        dead_letter: DeadLetterQueue | None = None,
        destinations: Sequence[str] | None = None,
    ) -> DispatchReport:
        """Send ``events`` to every route, or only to the named ones.

        ``destinations`` is the source's configured subset, resolved from validated config by
        the factory: ``None`` means the source routes to every enabled destination.
        """
        report = DispatchReport(routed=len(events))
        failed: set[str] = set()
        for route in self._routes_for(destinations):
            self._dispatch_route(
                route,
                events,
                source_id=source_id,
                dead_letter=dead_letter,
                report=report,
                failed=failed,
            )
        report.events_delivered = len(events) - len(failed)
        report.events_failed = len(failed)
        return report

    def _routes_for(self, destinations: Sequence[str] | None) -> list[Route]:
        if destinations is None:
            return self.routes
        wanted = set(destinations)
        return [route for route in self.routes if route.forwarder.id in wanted]

    def _dispatch_route(
        self,
        route: Route,
        events: Sequence[EcsEvent],
        *,
        source_id: str,
        dead_letter: DeadLetterQueue | None,
        report: DispatchReport,
        failed: set[str],
    ) -> None:
        destination = route.forwarder.id
        selected = [event for event in events if event.score >= route.severity_min]
        totals = report.totals(destination)
        totals["skipped"] += len(events) - len(selected)
        if not selected:
            return
        for batch in chunk(selected, route.batch_size):
            self._send_batch(
                route,
                batch,
                source_id=source_id,
                dead_letter=dead_letter,
                report=report,
                failed=failed,
            )

    def _send_batch(
        self,
        route: Route,
        batch: list[EcsEvent],
        *,
        source_id: str,
        dead_letter: DeadLetterQueue | None,
        report: DispatchReport,
        failed: set[str],
    ) -> None:
        destination = route.forwarder.id
        by_identity = {event.identity_key(): event for event in batch}
        try:
            result = retry_call(
                lambda: route.forwarder.send(batch),
                policy=route.retry_policy,
                name=f"{destination}:send",
                on_retry=partial(self._note_retry, destination),
            )
        except Exception as exc:
            totals = report.totals(destination)
            report.errors.append(f"{destination}: {exc}")
            self.metrics.incr("failed", source=destination, by=len(batch))
            self.log.exception(
                "destination batch failed",
                extra={
                    "destination": destination,
                    "source_id": source_id,
                    "batch_size": len(batch),
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
            )
            failed.update(by_identity)
            if dead_letter is not None:
                written = self._dead_letter_batch(
                    dead_letter, batch, destination=destination, error=exc
                )
                totals["dead_lettered"] += written
                report.dead_lettered += written
            return

        totals = report.totals(destination)
        totals["accepted"] += result.accepted
        report.accepted += result.accepted
        self.metrics.incr("forwarded", source=destination, by=result.accepted)
        if result.rejected:
            totals["rejected"] += len(result.rejected)
            report.rejected += len(result.rejected)
            self.metrics.incr("failed", source=destination, by=len(result.rejected))
            self._note_rejected_identities(
                result, destination=destination, failed=failed, report=report
            )
            if dead_letter is not None:
                written = self._dead_letter_rejections(
                    dead_letter, result, by_identity, destination=destination
                )
                totals["dead_lettered"] += written
                report.dead_lettered += written
        if result.error:
            report.errors.append(f"{destination}: {result.error}")

    def _note_rejected_identities(
        self,
        result: DeliveryResult,
        *,
        destination: str,
        failed: set[str],
        report: DispatchReport,
    ) -> None:
        """Remember which events this destination refused, even when it would not say.

        A refusal without an identity cannot be matched to an event, so it is counted under a
        key no real identity can collide with. Over-counting a failure is the safe direction for
        a SOC: the alternative is reporting an event as delivered when it may not have landed.
        """
        anonymous = 0
        for item in result.rejected:
            identity = str(item.get("identity", ""))
            if identity:
                failed.add(identity)
            else:
                anonymous += 1
        if anonymous:
            failed.update(f"?:{destination}:{offset}" for offset in range(anonymous))
            report.errors.append(
                f"{destination}: refused {anonymous} document(s) without naming their identity"
            )

    def _note_retry(
        self, destination: str, attempt: int, idle_seconds: float, error: BaseException
    ) -> None:
        self.metrics.incr("retried", source=destination)
        self.log.warning(
            "destination send failed, retrying",
            extra={
                "destination": destination,
                "attempt": attempt,
                "idle_seconds": round(idle_seconds, 3),
                "error_type": type(error).__name__,
            },
        )

    def _dead_letter_batch(
        self,
        dead_letter: DeadLetterQueue,
        batch: Sequence[EcsEvent],
        *,
        destination: str,
        error: BaseException,
    ) -> int:
        for event in batch:
            dead_letter.write(
                connector_id=destination,
                stage="forward",
                reason=f"destination {destination} failed the batch after retries",
                error=error,
                identity=event.identity_key(),
                document=self._document(event),
            )
        return len(batch)

    def _dead_letter_rejections(
        self,
        dead_letter: DeadLetterQueue,
        result: DeliveryResult,
        by_identity: dict[str, EcsEvent],
        *,
        destination: str,
    ) -> int:
        written = 0
        for rejection in result.rejected:
            identity = str(rejection.get("identity", ""))
            event = by_identity.get(identity)
            reason = rejection.get("reason", "unknown")
            dead_letter.write(
                connector_id=destination,
                stage="forward",
                reason=f"destination {destination} refused one document: {reason}",
                identity=identity or None,
                document=None if event is None else self._document(event),
            )
            written += 1
        return written

    def _document(self, event: EcsEvent) -> dict[str, Any]:
        return to_document(event, self.redaction)
