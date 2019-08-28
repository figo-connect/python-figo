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

#To call only once
def test_add_user():
  response = connection.add_user("John Doe", "john.doe@example.com", "password")
  assert response == {}

def test_create_token_and_session():
  token = connection.credential_login("john.doe@example.com", "password")
  pytest.token = token["access_token"]
  assert pytest.token
  pytest.session = FigoSession(token["access_token"])
  assert pytest.session.user.full_name == "John Doe"

def test_add_notification(access_token):
    notification = Notification(pytest.session)
    notification.notify_uri = "https://api.figo.me/callback"
    notification.observe_key = "/rest/transactions"
    notification.state = "4HgwtQP0jsjdz79h"
    response = pytest.session.add_notification(notification)
    pytest.notification = response
    assert response.notification_id != None

def test_notifications(access_token):
    response = pytest.session.notifications
    assert response != None

def test_modify_notification(access_token):
    pytest.notification.state="ZZZ"
    response = pytest.session.modify_notification(pytest.notification)
    assert response.state != None

def test_get_notification(access_token):
    response = pytest.session.get_notification(pytest.notification.notification_id)
    assert response.state != None

def test_remove_notification(access_token):
    response = pytest.session.remove_notification(pytest.notification.notification_id)
    assert response == None

def test_remove_user():
  response = pytest.session.remove_user()
  assert response == {}
