from opentelemetry import metrics
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import ConsoleMetricExporter, PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource


def setup_metrics(app_name: str):
    """Configure OpenTelemetry metrics."""

    resource = Resource.create({"service.name": app_name})

    # Reader 1: Prometheus (pull model) which serves /metrics
    # Note: This usually requires integrating with the web framework to expose the endpoint.
    # For now, we instantiate the reader.
    prometheus_reader = PrometheusMetricReader()

    # Reader 2: Console (for debugging/Phase 1 visibility)
    console_reader = PeriodicExportingMetricReader(ConsoleMetricExporter())

    provider = MeterProvider(resource=resource, metric_readers=[prometheus_reader, console_reader])

    metrics.set_meter_provider(provider)
