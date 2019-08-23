import pytest

from figo.models import User
from figo.models import TaskState
from figo.models import TaskToken

from figo import FigoConnection
from figo import FigoSession
from figo import FigoException

CREDENTIALS = ["john.doe@example.com", "password"]

def pytest_namespace():
    return {'session': '', 'token': ''}

def test_add_user(figo_connection):
  response = figo_connection.add_user("John Doe", "john.doe@example.com", "password")
  assert response == {}

def test_create_token_and_session(figo_connection):
  token = figo_connection.credential_login("john.doe@example.com", "password")
  pytest.token = token["access_token"]
  assert pytest.token
  pytest.session = FigoSession(token["access_token"])
  assert pytest.session.user.full_name == "John Doe"

def test_remove_user(figo_connection):
  response = pytest.session.remove_user()
  assert response == {}
