"""
Test configuration and fixtures.
"""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock

from app.main import app
from app.config.settings import settings


@pytest.fixture
def client():
    """Test client fixture."""
    return TestClient(app)


@pytest.fixture
def mock_cognito_client():
    """Mock Cognito client fixture."""
    return Mock()


@pytest.fixture
def test_settings():
    """Test settings fixture."""
    return settings
