"""Immutable actor and audit-event contracts; identity is resolved by callers."""

from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

from vulnops.workflow.states import CaseState


class ActorType(StrEnum):
    HUMAN = "HUMAN"
    SYSTEM = "SYSTEM"
    AGENT = "AGENT"


class Actor(BaseModel):
    """An attributed caller, not a credential or an authorisation grant."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    actor_type: ActorType
    actor_id: str = Field(min_length=1)

    @field_validator("actor_id")
    @classmethod
    def require_nonblank_id(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("actor_id must not be blank")
        return value


class CaseEventType(StrEnum):
    STATE_TRANSITION = "STATE_TRANSITION"


class CaseEvent(BaseModel):
    """Audit data returned with every successful transition, never published here."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    event_id: UUID = Field(default_factory=uuid4)
    case_id: UUID
    event_type: CaseEventType = CaseEventType.STATE_TRANSITION
    from_state: CaseState
    to_state: CaseState
    actor_type: ActorType
    actor_id: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    evidence_ids: tuple[UUID, ...] = Field(min_length=1, strict=False)
    correlation_id: UUID
    created_at: AwareDatetime

    @field_validator("actor_id", "reason")
    @classmethod
    def require_nonblank_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("actor_id and reason must not be blank")
        return value
