import logging
import sys

from opentelemetry._logs import set_logger_provider
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor, ConsoleLogRecordExporter

from .config import settings


def setup_logging() -> None:
    """Configure OpenTelemetry logging with Console exporter for Phase 1."""

    # 1. Setup OpenTelemetry Logger Provider
    logger_provider = LoggerProvider()

    # Export logs to console (stdout) as per requirements
    console_exporter = ConsoleLogRecordExporter()
    logger_provider.add_log_record_processor(BatchLogRecordProcessor(console_exporter))

    set_logger_provider(logger_provider)

    # 2. Attach OTel LoggingHandler to Python's root logger
    # This captures standard python logging calls and sends them to OTel
    handler = LoggingHandler(
        level=getattr(logging, settings.LOG_LEVEL), logger_provider=logger_provider
    )

    # Attach to root logger
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(settings.LOG_LEVEL)

    # Also keep a standard stream handler for immediate feedback if OTel fails or during startup
    # (Optional, but good for debugging if OTel batching delays output)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    )
    logging.getLogger().addHandler(stream_handler)

    # Silence noisy libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


logger = logging.getLogger("identity_platform")
