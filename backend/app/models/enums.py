import enum


class RunStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    NEEDS_INPUT = "needs_input"
    COMPLETE = "complete"
    FAILED = "failed"


class StageStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    NEEDS_INPUT = "needs_input"
    COMPLETE = "complete"
    FAILED = "failed"


class BusinessCriticality(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SystemClass(str, enum.Enum):
    IT = "it"
    ML = "ml"
    HYBRID = "hybrid"
