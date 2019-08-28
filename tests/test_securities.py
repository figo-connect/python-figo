import pytest
import os

from figo import FigoConnection
from figo import FigoSession
from figo.models import Notification

API_ENDPOINT = os.getenv("API_ENDPOINT")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
connection  = FigoConnection(CLIENT_ID, CLIENT_SECRET, "https://127.0.0.1/", api_endpoint=API_ENDPOINT)

def pytest_namespace():
  return {'session': '', 'token': '', 'access_id': '', 'sync_id': '', 'challenge_id': ''}

# To call only once
def test_add_user():
  response = connection.add_user("John Doe", "john.doe@example.com", "password")
  assert response == {}

def test_create_token_and_session():
  token = connection.credential_login("john.doe@example.com", "password")
  pytest.token = token["access_token"]
  assert pytest.token
  pytest.session = FigoSession(token["access_token"])
  assert pytest.session.user.full_name == "John Doe"

def test_get_securities(access_token):
  response = pytest.session.get_securities()
  assert response != None

def test_get_security(access_token):
  response = pytest.session.get_security(pytest.account_id,pytest.security_id)
  assert 1==2

