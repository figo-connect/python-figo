import pytest

from figo import FigoSession
from figo.models import Notification

from .conftest import PASSWORD


def pytest_configure():
    pytest.session = None
    pytest.token = None
    pytest.access_id = None
    pytest.sync_id = None
    pytest.challenge_id = None
    pytest.account_id = None
    pytest.new_user_id = None


# To call only once
def test_add_user(figo_connection, new_user_id):
    response = figo_connection.add_user("Jimmy", new_user_id, PASSWORD)
    pytest.new_user_id = new_user_id
    assert response == {}


def test_create_token_and_session(figo_connection):
    token = figo_connection.credential_login(pytest.new_user_id, PASSWORD)
    pytest.token = token["access_token"]
    assert pytest.token
    pytest.session = FigoSession(token["access_token"])
    assert pytest.session.user.full_name == "Jimmy"


def test_add_notification():
    notification = Notification(pytest.session)
    notification.notify_uri = "https://api.figo.me/callback"
    notification.observe_key = "/rest/transactions"
    notification.state = "4HgwtQP0jsjdz79h"
    response = pytest.session.add_notification(notification)
    pytest.notification = response
    assert response.notification_id is not None


def test_notifications():
    response = pytest.session.notifications
    assert response is not None


def test_modify_notification():
    pytest.notification.state = "ZZZ"
    response = pytest.session.modify_notification(pytest.notification)
    assert response.state is not None


def test_get_notification():
    response = pytest.session.get_notification(
        pytest.notification.notification_id
    )
    assert response.state is not None


def test_remove_notification():
    response = pytest.session.remove_notification(
        pytest.notification.notification_id
    )
    assert response is None


def test_remove_user():
    response = pytest.session.remove_user()
    assert response == {}
