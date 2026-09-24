"""
Base Service.

Generic application-layer service that concrete services subclass. Services
own business logic/orchestration and are the only layer that api/ routes
call directly — routes must never call repositories directly.
"""

from typing import Any, Generic, Sequence, TypeVar

from app.core.constants import DEFAULT_PAGE_SIZE
from app.core.exceptions import NotFoundError
from app.repositories.base import BaseRepository

ModelType = TypeVar("ModelType")


class BaseService(Generic[ModelType]):
    """
    Generic service wrapping a single BaseRepository.

    Usage (in a later part):
        class UserService(BaseService[User]):
            def __init__(self, repository: UserRepository):
                super().__init__(repository=repository)
    """

    def __init__(self, repository: BaseRepository):
        self.repository = repository

    def get_or_404(self, record_id: Any) -> ModelType:
        obj = self.repository.get_by_id(record_id)
        if obj is None:
            raise NotFoundError(f"Resource with id={record_id} not found.")
        return obj

    def list(self, skip: int = 0, limit: int = DEFAULT_PAGE_SIZE) -> Sequence[ModelType]:
        return self.repository.list(skip=skip, limit=limit)

    def create(self, obj: ModelType) -> ModelType:
        return self.repository.create(obj)

    def update(self, obj: ModelType) -> ModelType:
        return self.repository.update(obj)

    def delete(self, obj: ModelType) -> None:
        self.repository.delete(obj)
