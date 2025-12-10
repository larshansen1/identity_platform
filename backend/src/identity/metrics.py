"""OpenTelemetry metrics for Identity module."""

from collections.abc import Iterator

from opentelemetry import metrics

# Get meter for identity module
meter = metrics.get_meter("identity")

# Subject lifecycle counters
subjects_created_total = meter.create_counter(
    name="identity_subjects_created_total",
    description="Total subjects created",
    unit="1",
)

subjects_revoked_total = meter.create_counter(
    name="identity_subjects_revoked_total",
    description="Total subjects revoked",
    unit="1",
)

# Admin user gauge
admin_users_total = meter.create_up_down_counter(
    name="identity_admin_users_total",
    description="Current admin user count by role",
    unit="1",
)

# Bootstrap gauge - use a callback to report current state
_bootstrap_completed = False


def _get_bootstrap_completed(
    options: metrics.CallbackOptions,
) -> Iterator[metrics.Observation]:
    """Callback to report bootstrap status."""
    yield metrics.Observation(1 if _bootstrap_completed else 0, {})


bootstrap_completed_gauge = meter.create_observable_gauge(
    name="identity_bootstrap_completed",
    description="Bootstrap ran successfully (1=yes, 0=no)",
    unit="1",
    callbacks=[_get_bootstrap_completed],
)


class IdentityMetrics:
    """Facade for identity metrics with proper labels."""

    def record_subject_created(self, subject_type: str) -> None:
        """Record subject creation. Labels: type=machine_client|human_user"""
        subjects_created_total.add(1, {"type": subject_type})

    def record_subject_revoked(self, subject_type: str) -> None:
        """Record subject revocation. Labels: type=machine_client|human_user"""
        subjects_revoked_total.add(1, {"type": subject_type})

    def record_admin_created(self, role: str) -> None:
        """Record admin user creation."""
        admin_users_total.add(1, {"role": role})

    def record_bootstrap_completed(self) -> None:
        """Mark bootstrap as completed."""
        global _bootstrap_completed
        _bootstrap_completed = True


# Singleton instance
identity_metrics = IdentityMetrics()
