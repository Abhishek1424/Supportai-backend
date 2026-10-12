# What is this file?   Shared types for list endpoints (page, page_size, result list).
# Why?                 Every list API works the same, so the Flutter app can reuse
#                      ONE list/pagination widget.
# Flutter/Dart idea:   `PageParams` = query params object, `Page<T>` = a generic
#                      response model like `class Page<T> { List<T> items; int total; ... }`.
"""Shared pagination types used by every list endpoint.

Why: all list APIs behave identically (`page`, `page_size`, same response
envelope), so frontend list components can be written once.
"""

from typing import Annotated

from fastapi import Depends, Query
from pydantic import BaseModel

# Default and maximum rows per request. The maximum protects the database.
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100  # Caps how much data one request can pull; protects the database.


# Holds ?page= and ?page_size= from the URL. Dart idea: a small request model.
class PageParams(BaseModel):
    """Validated `?page=&page_size=` query parameters."""

    page: int
    page_size: int

    @property
    def offset(self) -> int:
        """Number of rows to skip for SQL OFFSET."""
        return (self.page - 1) * self.page_size


# Reads page and page_size from the URL query and checks the range (page >= 1, size 1..100).
# FastAPI turns the function parameters into URL query parameters automatically.
def get_page_params(
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
) -> PageParams:
    """FastAPI dependency that parses and bounds-checks pagination query params."""
    return PageParams(page=page, page_size=page_size)


# A shortcut name. "Dep" = dependency. Writing `params: PageParamsDep` in an endpoint
# means: "FastAPI, please create PageParams for me". Dart idea: a typedef + injection.
PageParamsDep = Annotated[PageParams, Depends(get_page_params)]


# A generic response model. `[T]` is like Dart's `<T>`: Page<Member>, Page<AuditLogEntry>.
class Page[T](BaseModel):
    """Standard list response envelope."""

    items: list[T]
    total: int
    page: int
    page_size: int
