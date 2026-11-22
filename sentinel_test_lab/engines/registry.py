"""Maps a test configuration to the engine that executes it."""

from __future__ import annotations

from ..core.models import Backend, TestConfig, TestType
from .base import Engine


def engine_for(config: TestConfig) -> Engine:
    if config.test_type == TestType.LOAD:
        if config.backend == Backend.LOCUST:
            from ..integrations.locust.adapter import LocustLoadEngine

            return LocustLoadEngine()
        if config.backend == Backend.K6:
            from ..integrations.k6.adapter import K6LoadEngine

            return K6LoadEngine()
        from .load.engine import LoadEngine

        return LoadEngine()
    if config.test_type == TestType.STRESS:
        from .stress.engine import StressEngine

        return StressEngine()
    if config.test_type == TestType.SPIKE:
        from .spike.engine import SpikeEngine

        return SpikeEngine()
    if config.test_type == TestType.FLOOD:
        from .resilience.flood import FloodResilienceEngine

        return FloodResilienceEngine()
    if config.test_type == TestType.DDOS_POSTURE:
        from .resilience.ddos_posture import DdosPostureEngine

        return DdosPostureEngine()
    if config.test_type == TestType.BRUTE_FORCE:
        from .resilience.bruteforce import BruteForceProtectionEngine

        return BruteForceProtectionEngine()
    if config.test_type == TestType.SECURITY:
        from .security.assessment import SecurityAssessmentEngine

        return SecurityAssessmentEngine()
    raise ValueError(f"Unsupported test type: {config.test_type}")
