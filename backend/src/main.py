from contextlib import asynccontextmanager

from fastapi import FastAPI
from opentelemetry import trace
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.logging import LoggingInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from shared.config import settings
from shared.database import engine
from shared.logging import setup_logging
from shared.metrics import setup_metrics


# Setup OpenTelemetry Tracing
def setup_tracing():
    resource = Resource.create({"service.name": settings.APP_NAME})
    provider = TracerProvider(resource=resource)

    # Export traces to console for Phase 1
    processor = BatchSpanProcessor(ConsoleSpanExporter())
    provider.add_span_processor(processor)

    trace.set_tracer_provider(provider)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    setup_logging()
    setup_tracing()
    setup_metrics(settings.APP_NAME)

    LoggingInstrumentor().instrument(set_logging_format=True)
    SQLAlchemyInstrumentor().instrument(
        engine=engine.sync_engine
    )  # Need sync engine for instrumentation usually

    yield
    # Shutdown
    # (Providers usually verify cleanup automatically, or we can force flush here)


app = FastAPI(title=settings.APP_NAME, lifespan=lifespan)

# Instrument FastAPI
FastAPIInstrumentor.instrument_app(app)


@app.get("/health")
async def health_check():
    return {"status": "ok", "service": settings.APP_NAME}


# Prometheus endpoint (Manual exposition if not using a middleware library)
# For production, we'd use starlette-prometheus or similar.
# The `opentelemetry-exporter-prometheus` reader exposes a WSGI app,
# but integrating it into FastAPI usually requires a manual route or middleware.
# For Phase 1, we rely on the Console exporter for verification.
