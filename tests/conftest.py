import pytest
from starlette.testclient import TestClient

from main import app


@pytest.fixture(scope='module')
def test_client():
    with TestClient(app) as client:
        yield client
