"""Cursor pagination, including the guard against a source that re-offers the same window."""

from __future__ import annotations

import itertools
from collections.abc import Callable
from logging import LogRecord

import pytest

from soc_connectors.exceptions import PaginationError
from soc_connectors.utils.pagination import Page, flatten, paginate

pytestmark = pytest.mark.unit


def script(
    specs: list[tuple[list[int], str | None]],
) -> tuple[Callable[[str | None], Page], list[str | None]]:
    """A fetch_page double over fixed pages that records the cursors it was called with."""
    pages = [Page(items=list(items), next_cursor=cursor) for items, cursor in specs]
    calls: list[str | None] = []

    def fetch(cursor: str | None) -> Page:
        calls.append(cursor)
        return pages[len(calls) - 1]

    return fetch, calls


def test_page_helpers() -> None:
    assert Page(items=[1, 2, 3]).count == 3
    assert not Page(items=[1]).is_empty
    assert Page().is_empty
    assert flatten([Page(items=[1, 2]), Page(items=[3])]) == [1, 2, 3]


def test_pagination_walks_the_cursors_in_order() -> None:
    fetch, calls = script([([1, 2], "b"), ([3], "c"), ([4], None)])
    collected = list(paginate(fetch, start_cursor="a"))
    assert [page.count for page in collected] == [2, 1, 1]
    assert calls == ["a", "b", "c"]


def test_pagination_stops_when_no_cursor_is_offered() -> None:
    fetch, calls = script([([1, 2], None)])
    assert len(list(paginate(fetch))) == 1
    assert calls == [None]


def test_repeated_cursor_raises_instead_of_looping() -> None:
    fetch, _ = script([([1], "same"), ([1], "same")])
    with pytest.raises(PaginationError, match="twice in one cycle"):
        list(paginate(fetch))


def test_a_cursor_that_ignores_history_is_caught_too() -> None:
    fetch, _ = script([([1], "b"), ([2], "c"), ([3], "a")])
    with pytest.raises(PaginationError):
        list(paginate(fetch, start_cursor="a"))


def test_max_pages_caps_a_source_that_never_stops() -> None:
    issued = itertools.count()

    def fetch(_cursor: str | None) -> Page:
        return Page(items=[1], next_cursor=f"cursor-{next(issued)}")

    assert len(list(paginate(fetch, start_cursor="0", max_pages=3))) == 3


def test_an_explicit_end_is_not_a_warning(capture_logs: Callable[[str], list[LogRecord]]) -> None:
    records = capture_logs("pagination")
    assert list(paginate(lambda _cursor: Page(items=[1], next_cursor=None))) == [Page(items=[1])]
    assert not any("gave no cursor" in record.getMessage() for record in records)


def test_more_pages_promised_but_no_cursor_stops_the_cycle(
    capture_logs: Callable[[str], list[LogRecord]],
) -> None:
    records = capture_logs("pagination")

    def fetch(_cursor: str | None) -> Page:
        return Page(items=[1, 2], next_cursor=None, has_more=True)

    assert len(list(paginate(fetch))) == 1
    assert any("gave no cursor" in record.getMessage() for record in records)


def test_zero_max_pages_is_a_configuration_bug_not_an_empty_run() -> None:
    with pytest.raises(PaginationError, match="max_pages"):
        list(paginate(lambda _cursor: Page(), max_pages=0))
