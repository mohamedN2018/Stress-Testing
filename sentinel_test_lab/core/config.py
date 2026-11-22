"""Application paths, safety limits and persisted settings."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SafetyLimits:
    """Upper bounds applied to a single test run."""

    max_users: int
    max_duration_s: int
    max_rps: float
    max_request_budget: int

    def clamp_to(self, ceiling: "SafetyLimits") -> "SafetyLimits":
        return SafetyLimits(
            max_users=max(1, min(self.max_users, ceiling.max_users)),
            max_duration_s=max(1, min(self.max_duration_s, ceiling.max_duration_s)),
            max_rps=max(0.1, min(self.max_rps, ceiling.max_rps)),
            max_request_budget=max(1, min(self.max_request_budget, ceiling.max_request_budget)),
        )


# Safe defaults: used for every target unless higher limits are explicitly
# configured, the target is trusted, and the run is explicitly confirmed.
DEFAULT_LIMITS = SafetyLimits(max_users=5, max_duration_s=60, max_rps=5.0, max_request_budget=300)

# Hard ceilings compiled into the application. No setting can exceed them.
ABSOLUTE_LIMITS = SafetyLimits(
    max_users=200, max_duration_s=900, max_rps=200.0, max_request_budget=100_000
)

# Extra hard caps for the sensitive assessment modules.
FLOOD_MAX_DURATION_S = 30
FLOOD_MAX_RPS = 50.0
BRUTE_FORCE_MAX_ATTEMPTS = 20
BRUTE_FORCE_MIN_INTERVAL_S = 0.5
ACTIVE_SCAN_MAX_DURATION_S = 300


@dataclass
class Thresholds:
    """Automatic stop conditions evaluated while a test is running."""

    max_error_rate: float = 0.25
    max_p95_ms: float = 8000.0
    max_consecutive_failures: int = 15
    min_samples: int = 20
    window_s: float = 5.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "Thresholds":
        data = data or {}
        names = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in names})


@dataclass
class Settings:
    """User-configurable settings persisted in SQLite."""

    elevated_enabled: bool = False
    elevated_max_users: int = 50
    elevated_max_duration_s: int = 300
    elevated_max_rps: float = 50.0
    elevated_max_request_budget: int = 15_000
    thresholds: Thresholds = field(default_factory=Thresholds)
    request_timeout_s: float = 10.0
    k6_path: str = ""
    locust_path: str = ""
    zap_url: str = ""
    zap_path: str = ""  # folder of a local ZAP installation (empty = default location)
    cloudflare_api_base: str = "https://api.cloudflare.com/client/v4"

    def elevated_limits(self) -> SafetyLimits:
        return SafetyLimits(
            max_users=self.elevated_max_users,
            max_duration_s=self.elevated_max_duration_s,
            max_rps=self.elevated_max_rps,
            max_request_budget=self.elevated_max_request_budget,
        ).clamp_to(ABSOLUTE_LIMITS)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["thresholds"] = self.thresholds.to_dict()
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "Settings":
        data = dict(data or {})
        thresholds = Thresholds.from_dict(data.pop("thresholds", None))
        names = {f.name for f in fields(cls)} - {"thresholds"}
        return cls(thresholds=thresholds, **{k: v for k, v in data.items() if k in names})


@dataclass(frozen=True)
class AppPaths:
    data_dir: Path

    @property
    def db_path(self) -> Path:
        return self.data_dir / "sentinel.db"

    @property
    def log_dir(self) -> Path:
        return self.data_dir / "logs"

    @property
    def audit_file(self) -> Path:
        return self.log_dir / "audit.jsonl"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def work_dir(self) -> Path:
        return self.data_dir / "work"

    def ensure(self) -> "AppPaths":
        for path in (self.data_dir, self.log_dir, self.reports_dir, self.work_dir):
            path.mkdir(parents=True, exist_ok=True)
        return self

    @classmethod
    def default(cls) -> "AppPaths":
        override = os.environ.get("SENTINEL_DATA_DIR")
        if override:
            return cls(Path(override))
        base = os.environ.get("APPDATA") or str(Path.home() / ".local" / "share")
        return cls(Path(base) / "SentinelTestLab")
