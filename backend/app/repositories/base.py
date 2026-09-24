"""
Base Repository.

Generic CRUD repository that concrete repositories (added alongside their
domain's models, starting Part 3+) will subclass. Contains ONLY data-access
logic — no business rules, no HTTP concerns.
"""

from typing import Any, Generic, Sequence, Type, TypeVar

from sqlalchemy.orm import Session

from app.core.constants import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.database import Base

ModelType = TypeVar("ModelType", bound=Base)


class BaseRepository(Generic[ModelType]):
    """
    Generic repository providing common CRUD operations for a single
    SQLAlchemy model.

    Usage (in a later part):
        class UserRepository(BaseRepository[User]):
            def __init__(self, db: Session):
                super().__init__(model=User, db=db)
    """

    def __init__(self, model: Type[ModelType], db: Session | None = None, session: Session | None = None):
        self.model = model
        self.db = db if db is not None else session

    @property
    def session(self) -> Session:
        return self.db

    def get_by_id(self, record_id: Any) -> ModelType | None:
        return self.db.get(self.model, record_id)

    def list(self, skip: int = 0, limit: int = DEFAULT_PAGE_SIZE) -> Sequence[ModelType]:
        limit = min(limit, MAX_PAGE_SIZE)
        return self.db.query(self.model).offset(skip).limit(limit).all()

    def create(self, obj: ModelType) -> ModelType:
        self.db.add(obj)
        self.db.commit()
        self.db.refresh(obj)
        return obj

    def update(self, obj: ModelType) -> ModelType:
        self.db.merge(obj)
        self.db.commit()
        return obj

    def delete(self, obj: ModelType) -> None:
        self.db.delete(obj)
        self.db.commit()
