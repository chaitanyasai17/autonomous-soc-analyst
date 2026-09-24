"""
Base response schemas.

Defines the standard API response envelope used across all endpoints, so
every consumer of the API (frontend, external integrations) gets a
consistent shape regardless of which resource they're calling.
"""

import math
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, computed_field

DataT = TypeVar("DataT")


class BaseSchema(BaseModel):
    """Base class for all Pydantic schemas — enables ORM attribute reading."""

    model_config = ConfigDict(from_attributes=True)


class ResponseSchema(BaseSchema, Generic[DataT]):
    """Standard single-resource response envelope."""

    success: bool = True
    message: str | None = None
    data: DataT | None = None


class PaginatedResponseSchema(BaseSchema, Generic[DataT]):
    """
    Standard paginated list response envelope.

    `total_pages`, `current_page`, `has_next`, and `has_previous` (added in
    Part 7 for enterprise pagination) are `@computed_field` properties
    derived from total/skip/limit — every existing call site across Parts
    4-6 that constructs this schema with only (data, total, skip, limit)
    continues to work unmodified; the derived fields simply appear in the
    serialized response automatically.
    """

    success: bool = True
    message: str | None = None
    data: list[DataT]
    total: int
    skip: int
    limit: int

    @computed_field
    @property
    def current_page(self) -> int:
        return (self.skip // self.limit) + 1 if self.limit > 0 else 1

    @computed_field
    @property
    def total_pages(self) -> int:
        return max(1, math.ceil(self.total / self.limit)) if self.limit > 0 else 1

    @computed_field
    @property
    def has_next(self) -> bool:
        return self.skip + self.limit < self.total

    @computed_field
    @property
    def has_previous(self) -> bool:
        return self.skip > 0


class ErrorResponseSchema(BaseSchema):
    """Standard error response envelope (mirrors core/exceptions.py handlers)."""

    success: bool = False
    message: str
    details: object | None = None
