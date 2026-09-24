"""WebSecurityAllowlistRepository — repository for target allowlist."""

from __future__ import annotations

import uuid
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.web_security_allowlist import WebSecurityAllowlist
from app.repositories.base import BaseRepository


class WebSecurityAllowlistRepository(BaseRepository[WebSecurityAllowlist]):
    def __init__(self, session: Session):
        super().__init__(WebSecurityAllowlist, session)

    def list_active(self) -> Sequence[WebSecurityAllowlist]:
        stmt = select(WebSecurityAllowlist).where(WebSecurityAllowlist.is_active == True)
        return self.session.execute(stmt).scalars().all()

    def get_by_pattern(self, pattern: str) -> WebSecurityAllowlist | None:
        stmt = select(WebSecurityAllowlist).where(WebSecurityAllowlist.pattern == pattern.strip().lower())
        return self.session.execute(stmt).scalar_one_or_none()

    def search(
        self,
        skip: int = 0,
        limit: int = 100,
    ) -> tuple[Sequence[WebSecurityAllowlist], int]:
        stmt = select(WebSecurityAllowlist).order_by(WebSecurityAllowlist.created_at.desc())
        items = self.session.execute(stmt.offset(skip).limit(limit)).scalars().all()
        total = self.session.execute(select(WebSecurityAllowlist)).scalars().all()
        return items, len(total)
