"""Shared pagination types used by every list endpoint.

Why: all list APIs behave identically (`page`, `page_size`, same response
envelope), so frontend list components can be written once.
"""

from typing import Annotated

from fastapi import Depends, Query
from pydantic import BaseModel

DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100  # Caps how much data one request can pull; protects the database.


class PageParams(BaseModel):
    """Validated `?page=&page_size=` query parameters."""

    page: int
    page_size: int

    @property
    def offset(self) -> int:
        """Number of rows to skip for SQL OFFSET."""
        return (self.page - 1) * self.page_size


def get_page_params(
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
) -> PageParams:
    """FastAPI dependency that parses and bounds-checks pagination query params."""
    return PageParams(page=page, page_size=page_size)


PageParamsDep = Annotated[PageParams, Depends(get_page_params)]


class Page[T](BaseModel):
    """Standard list response envelope."""

    items: list[T]
    total: int
    page: int
    page_size: int
