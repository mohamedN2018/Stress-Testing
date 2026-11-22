"""Domain models shared by the engines, the orchestrator, storage and the UI."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from .config import Thresholds


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class TestType(StrEnum):
    __test__ = False  # not a pytest class

    LOAD = "load"
    STRESS = "stress"
    SPIKE = "spike"
    FLOOD = "flood"
    DDOS_POSTURE = "ddos_posture"
    BRUTE_FORCE = "brute_force"
    SECURITY = "security"


class Environment(StrEnum):
    PRODUCTION = "production"
    STAGING = "staging"
    LOCALHOST = "localhost"


class RunStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    STOPPED = "stopped"  # stopped by the user (emergency stop / cancel)
    AUTO_STOPPED = "auto_stopped"  # stopped by the safety engine
    FAILED = "failed"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3}[self.value]


class Backend(StrEnum):
    INTERNAL = "internal"
    LOCUST = "locust"
    K6 = "k6"


@dataclass(frozen=True)
class LoadStage:
    """One step of a load profile.

    With ``ramp=True`` the number of virtual users moves linearly from the
    previous stage's level to ``users`` over ``duration_s``.
    """

    duration_s: float
    users: int
    label: str = ""
    ramp: bool = False


@dataclass
class AuthorizedTarget:
    """A target explicitly placed in the authorized scope by the user."""

    name: str
    base_url: str
    scheme: str
    host: str
    port: int
    environment: Environment
    authorization_statement: str
    description: str = ""
    authorized_at: str = field(default_factory=utcnow_iso)
    allowed_paths: list[str] = field(default_factory=lambda: ["/"])
    allowed_methods: list[str] = field(default_factory=lambda: ["GET", "HEAD"])
    pinned_ips: list[str] = field(default_factory=list)
    allow_private: bool = False
    network_class: str = "public"  # public | private | loopback (from DNS resolution)
    ownership_verified: bool = False
    verify_token: str = ""
    verify_tls: bool = True
    id: int | None = None

    @property
    def is_local(self) -> bool:
        return self.allow_private and self.network_class == "loopback"

    @property
    def is_trusted(self) -> bool:
        """Trusted targets may use elevated limits and the sensitive modules."""
        return self.is_local or self.ownership_verified

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["environment"] = self.environment.value
        return data


@dataclass
class TestConfig:
    __test__ = False

    test_type: TestType
    name: str
    users: int = 5
    duration_s: float = 30.0
    ramp_up_s: float = 0.0
    requests_per_user: int = 0  # 0 = bounded by duration/budget only
    interval_s: float = 1.0
    method: str = "GET"
    paths: list[str] = field(default_factory=lambda: ["/"])
    rate_limit_rps: float = 5.0
    request_budget: int = 0  # 0 = derived by the safety manager
    timeout_s: float = 10.0
    thresholds: Thresholds = field(default_factory=Thresholds)
    backend: Backend = Backend.INTERNAL
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["test_type"] = self.test_type.value
        data["backend"] = self.backend.value
        # never persist secrets that an engine may need at run time
        data["extra"] = {k: v for k, v in self.extra.items() if not k.startswith("_")}
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TestConfig":
        data = dict(data)
        data["test_type"] = TestType(data["test_type"])
        data["backend"] = Backend(data.get("backend", "internal"))
        data["thresholds"] = Thresholds.from_dict(data.get("thresholds"))
        return cls(**data)


@dataclass
class Finding:
    severity: Severity
    category: str
    title: str
    detail: str = ""
    recommendation: str = ""
    evidence: str = ""
    cwe: str = ""
    owasp: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        data = dict(data)
        data["severity"] = Severity(data["severity"])
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class EngineOutcome:
    """What an engine reports back besides the raw metrics."""

    findings: list[Finding] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class RunRecord:
    """A persisted test run."""

    name: str
    test_type: TestType
    target_id: int | None
    target_url: str
    status: RunStatus
    started_at: str
    config: dict[str, Any]
    backend: str = "internal"
    finished_at: str | None = None
    stop_reason: str = ""
    summary: dict[str, Any] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    series: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "test_type": self.test_type.value,
            "target_id": self.target_id,
            "target_url": self.target_url,
            "status": self.status.value,
            "backend": self.backend,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "stop_reason": self.stop_reason,
            "config": self.config,
            "summary": self.summary,
            "details": self.details,
            "series": self.series,
            "findings": [f.to_dict() for f in self.findings],
        }
