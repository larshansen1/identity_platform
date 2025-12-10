import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

# Import modules to test
from shared.logging import setup_logging
from shared.metrics import setup_metrics
from main import app

client = TestClient(app)

def test_setup_logging():
    """Test that setup_logging configures OTel provider."""
    with patch("shared.logging.set_logger_provider") as mock_set_provider, \
         patch("shared.logging.LoggerProvider") as mock_provider_cls, \
         patch("shared.logging.BatchLogRecordProcessor"), \
         patch("shared.logging.ConsoleLogRecordExporter"):
        
        setup_logging()
        
        mock_provider_cls.assert_called_once()
        mock_provider_cls.assert_called_once()
        mock_set_provider.assert_called_once()



def test_setup_metrics():
    """Test that setup_metrics configures OTel meter provider."""
    # We mock the entire metrics module or specific functions
    with patch("shared.metrics.MeterProvider") as mock_provider_cls, \
         patch("shared.metrics.metrics.set_meter_provider") as mock_set_provider, \
         patch("shared.metrics.PeriodicExportingMetricReader"), \
         patch("shared.metrics.ConsoleMetricExporter"):
        
        setup_metrics("test-app")
        
        mock_provider_cls.assert_called_once()
        mock_set_provider.assert_called_once()

@pytest.mark.asyncio
async def test_get_db_dependencies():
    """Test get_db and get_db_context generators."""
    from shared.database import get_db, get_db_context
    
    # Mock the AsyncSessionLocal to return a mock session
    with patch("shared.database.AsyncSessionLocal") as mock_maker:
        mock_session = MagicMock()
        # Async mock for context manager __aenter__ and __aexit__
        mock_session.__aenter__.return_value = mock_session
        mock_session.__aexit__.return_value = None
        mock_maker.return_value = mock_session
        
        # Test get_db
        async for session in get_db():
            assert session == mock_session
            
        # Test get_db_context
        async with get_db_context() as session:
            assert session == mock_session

def test_health_check():
    """Test the /health endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert "service" in response.json()

def test_app_startup_and_lifespan():
    """Test that lifespan startup events run without error."""
    # TestClient automatically runs lifespan on context enter/exit
    # Mock the setup functions to prevent real OTel background threads from starting,
    # but allow the setup functions themselves to run to ensure coverage.
    with patch("main.Resource"), \
         patch("main.TracerProvider"), \
         patch("main.BatchSpanProcessor"), \
         patch("main.ConsoleSpanExporter"), \
         patch("main.trace"), \
         patch("main.LoggingInstrumentor"), \
         patch("main.SQLAlchemyInstrumentor"), \
         patch("shared.logging.LoggerProvider"), \
         patch("shared.logging.BatchLogRecordProcessor"), \
         patch("shared.logging.set_logger_provider"), \
         patch("shared.logging.ConsoleLogRecordExporter"), \
         patch("shared.metrics.MeterProvider"), \
         patch("shared.metrics.PeriodicExportingMetricReader"), \
         patch("shared.metrics.metrics.set_meter_provider"):
         
        with TestClient(app) as local_client:
            response = local_client.get("/health")
            assert response.status_code == 200
