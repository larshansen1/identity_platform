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

# ============================================================================
# Phase 3: Certificate Authority Metrics
# ============================================================================

# Certificate request counters
certificate_requests_created_total = meter.create_counter(
    name="identity_certificate_requests_created_total",
    description="Total certificate requests created",
    unit="1",
)

certificate_requests_approved_total = meter.create_counter(
    name="identity_certificate_requests_approved_total",
    description="Total certificate requests approved",
    unit="1",
)

certificate_requests_rejected_total = meter.create_counter(
    name="identity_certificate_requests_rejected_total",
    description="Total certificate requests rejected",
    unit="1",
)

certificate_requests_expired_total = meter.create_counter(
    name="identity_certificate_requests_expired_total",
    description="Total certificate requests expired",
    unit="1",
)

# Certificate generation counters
certificates_generated_total = meter.create_counter(
    name="identity_certificates_generated_total",
    description="Total certificates generated",
    unit="1",
)

certificates_downloaded_total = meter.create_counter(
    name="identity_certificates_downloaded_total",
    description="Total certificates downloaded",
    unit="1",
)

# Certificate generation histogram
certificate_generation_duration = meter.create_histogram(
    name="identity_certificate_generation_duration_seconds",
    description="Certificate generation duration in seconds",
    unit="s",
)

# Validation counters
certificate_validations_total = meter.create_counter(
    name="identity_certificate_validations_total",
    description="Total certificate validations",
    unit="1",
)

# CA metrics
ca_certificates_signed_total = meter.create_counter(
    name="identity_ca_certificates_signed_total",
    description="Total certificates signed by CA",
    unit="1",
)

# Revocation counters
certificates_revoked_total = meter.create_counter(
    name="identity_certificates_revoked_total",
    description="Total certificates revoked",
    unit="1",
)

certificate_revocation_checks_total = meter.create_counter(
    name="identity_certificate_revocation_checks_total",
    description="Total revocation checks performed",
    unit="1",
)

# CA key loaded gauge - track storage type
_ca_key_storage_type: str | None = None


def _get_ca_key_loaded(
    options: metrics.CallbackOptions,
) -> Iterator[metrics.Observation]:
    """Callback to report CA key loaded status."""
    if _ca_key_storage_type:
        yield metrics.Observation(1, {"storage_type": _ca_key_storage_type})
    else:
        yield metrics.Observation(0, {"storage_type": "none"})


ca_key_loaded_gauge = meter.create_observable_gauge(
    name="identity_ca_key_loaded",
    description="CA key loaded (1=yes, 0=no)",
    unit="1",
    callbacks=[_get_ca_key_loaded],
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

    # ========================================================================
    # Phase 3: Certificate Authority Metrics
    # ========================================================================

    def record_certificate_request_created(self, request_type: str) -> None:
        """Record certificate request creation. Labels: type=initial|renewal"""
        certificate_requests_created_total.add(1, {"type": request_type})

    def record_certificate_request_approved(self) -> None:
        """Record certificate request approval."""
        certificate_requests_approved_total.add(1)

    def record_certificate_request_rejected(self) -> None:
        """Record certificate request rejection."""
        certificate_requests_rejected_total.add(1)

    def record_certificate_request_expired(self) -> None:
        """Record certificate request expiration."""
        certificate_requests_expired_total.add(1)

    def record_certificate_generated(self, duration_seconds: float) -> None:
        """Record certificate generation with duration."""
        certificates_generated_total.add(1)
        ca_certificates_signed_total.add(1)
        certificate_generation_duration.record(duration_seconds)

    def record_certificate_downloaded(self) -> None:
        """Record certificate download."""
        certificates_downloaded_total.add(1)

    def record_certificate_validation(self, result: str) -> None:
        """Record certificate validation. Labels: result=valid|invalid"""
        certificate_validations_total.add(1, {"result": result})

    def record_certificate_revoked(self, reason: str) -> None:
        """Record certificate revocation. Labels: reason=client_deleted|manual"""
        certificates_revoked_total.add(1, {"reason": reason})

    def record_revocation_check(self, result: str) -> None:
        """Record revocation check. Labels: result=revoked|valid"""
        certificate_revocation_checks_total.add(1, {"result": result})

    def record_ca_key_loaded(self, storage_type: str) -> None:
        """Record CA key loaded with storage type."""
        global _ca_key_storage_type
        _ca_key_storage_type = storage_type


# Singleton instance
identity_metrics = IdentityMetrics()
