"""Pagination that cannot loop forever.

CloudTrail's S3 listing, Microsoft Graph's ``@odata.nextLink`` and a syslog file tail all
page, all with a different token in the response. The framework needs one contract: hand me a
cursor, give me items plus the next cursor, and stop. The guard here is against the real
failure mode — an API that hands back the token it was given, which would otherwise re-read
the same window inside a single cycle until the process is killed.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any

from soc_connectors.exceptions import PaginationError
from soc_connectors.logging_setup import get_logger

DEFAULT_MAX_PAGES = 100
logger = get_logger("pagination")


@dataclass(slots=True)
class Page:
    """One page of results plus the opaque cursor needed to fetch the next one."""

    items: Sequence[Any] = field(default_factory=list)
    next_cursor: str | None = None
    has_more: bool | None = None

    @property
    def count(self) -> int:
        return len(self.items)

    @property
    def is_empty(self) -> bool:
        return not self.items


def paginate(
    fetch_page: Callable[[str | None], Page],
    *,
    start_cursor: str | None = None,
    max_pages: int = DEFAULT_MAX_PAGES,
) -> Iterator[Page]:
    """Yield pages until the source stops offering a cursor, ``max_pages`` is reached, or a
    cursor repeats.

    A repeated cursor raises rather than warns: continuing would burn the polling interval on
    the same window and the operator would see "0 new events" forever.
    """
    if max_pages < 1:
        raise PaginationError(f"max_pages must be at least 1, got {max_pages}")
    cursor = start_cursor
    seen: set[str] = set()
    for page_number in range(1, max_pages + 1):
        page = fetch_page(cursor)
        yield page
        if cursor is not None:
            seen.add(cursor)
        following = page.next_cursor
        if following is None:
            if page.has_more:
                logger.warning(
                    "source reported more pages but gave no cursor; stopping the cycle",
                    extra={"page": page_number, "items": page.count},
                )
            return
        if following in seen or following == cursor:
            raise PaginationError(
                f"source returned cursor {following!r} twice in one cycle (page {page_number}); "
                "refusing to re-read the same window"
            )
        cursor = following
    logger.info("page limit reached", extra={"max_pages": max_pages, "cursor": cursor})


def flatten(pages: Iterable[Page]) -> list[Any]:
    """Collect every item from a sequence of pages."""
    return [item for page in pages for item in page.items]
