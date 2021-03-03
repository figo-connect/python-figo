import time

import pytest
from dotenv import load_dotenv

from figo import FigoSession
from figo.models import Account, Challenge, Sync

from .conftest import PASSWORD

load_dotenv()

# DEMO_PUPPETEER_2_BANK_ID (BLZ: "90090078"):
CREDENTIALS = {"login_id": "user1", "password": "123456"}
CONSENT = {
    "recurring": True,
    "period": 90,
    "scopes": ["ACCOUNTS", "BALANCES", "TRANSACTIONS"],
}
ACCESS_METHOD_ID = "a08d3799-7c08-4ccb-a1b2-e38aba988266"
TAN_2FA = "user12fa"


def pytest_configure():
    pytest.session = None
    pytest.token = None
    pytest.access_id = None
    pytest.sync_id = None
    pytest.challenge_id = None
    pytest.account_id = None
    pytest.payments_token = None
    pytest.new_user_id = None


def test_add_user(figo_connection, new_user_id):
    response = figo_connection.add_user("Jimmy", new_user_id, PASSWORD)
    pytest.new_user_id = new_user_id
    assert response == {}


def test_get_version(figo_connection):
    response = figo_connection.get_version()
    assert response == {"environment": "staging", "version": "20.18.6"}


def test_create_token_and_session(figo_connection):
    token = figo_connection.credential_login(pytest.new_user_id, PASSWORD)
    pytest.token = token["access_token"]

    pytest.session = FigoSession(pytest.token)
    assert pytest.session.user.full_name == "Jimmy"


def test_create_token_for_payments(figo_connection):
    token = figo_connection.credential_login(
        pytest.new_user_id, PASSWORD, scope="payments=rw"
    )
    pytest.payments_token = token["access_token"]
    assert token["scope"] == "payments=rw"


def test_add_access():
    response = pytest.session.add_access(
        ACCESS_METHOD_ID, CREDENTIALS, CONSENT
    )
    assert "id" in response
    pytest.access_id = response["id"]


def test_add_access_with_wrong_access_id():
    access_method_id = "pipopipo-pipo-pipo-pipo-pipopipopipo"
    response = pytest.session.add_access(
        access_method_id, CREDENTIALS, CONSENT
    )
    assert "error" in response
    err_data = response["error"]["data"]
    assert err_data["access_method_id"] == ["Unknown method identifier."]


def test_get_accesses():
    accesses = pytest.session.get_accesses()
    assert len(accesses) > 0


def test_get_access():
    accesses = pytest.session.get_access(pytest.access_id)
    assert len(accesses) > 0


def test_add_sync():
    response = pytest.session.add_sync(
        pytest.access_id, None, None, None, None, None
    )
    assert isinstance(response, Sync)
    pytest.sync_id = response.id
    assert response.status == "QUEUED"


def test_get_synchronization_status():
    status = "QUEUED"
    count = 0
    while status in ["QUEUED", "RUNNING"]:
        time.sleep(1)
        response = pytest.session.get_synchronization_status(
            pytest.access_id, pytest.sync_id
        )
        status = response.status
        assert count < 20
        count += 1

    assert response.status == "AWAIT_AUTH"
    assert isinstance(response, Sync)
    pytest.challenge_id = response.challenge.id


def test_solve_synchronization_challenge():
    payload = {"value": TAN_2FA}
    response = pytest.session.solve_synchronization_challenge(
        pytest.access_id, pytest.sync_id, pytest.challenge_id, payload
    )
    assert response == {}


def test_get_sync_after_challenge():
    status = "QUEUED"
    count = 0
    while status in ["QUEUED", "RUNNING"]:
        time.sleep(1)
        response = pytest.session.get_synchronization_status(
            pytest.access_id, pytest.sync_id
        )
        status = response.status
        assert count < 20
        count += 1

    assert response.status == "COMPLETED"
    assert isinstance(response, Sync)


def test_get_synchronization_challenges():
    response = pytest.session.get_synchronization_challenges(
        pytest.access_id, pytest.sync_id
    )
    assert len(response) > 0


def test_get_synchronization_challenge():
    response = pytest.session.get_synchronization_challenge(
        pytest.access_id, pytest.sync_id, pytest.challenge_id
    )
    assert isinstance(response, Challenge)


def test_get_accounts():
    response = pytest.session.get_accounts()
    pytest.account_id = response[0].account_id
    assert isinstance(response[0], Account)
    assert isinstance(response[0].account_id, str)


def test_get_account():
    response = pytest.session.get_account(pytest.account_id)
    assert isinstance(response, Account)


def test_get_account_balance():
    response = pytest.session.get_account_balance(pytest.account_id)
    assert response.balance in [-4040.0, 0.0]


# TODO: check response API
def test_get_securities():
    response = pytest.session.get_securities()
    assert response is not None


def test_get_payments():
    session = FigoSession(pytest.payments_token)
    response = session.get_payments(pytest.account_id, None, None, None, None)
    assert response == []


def test_get_standing_orders():
    response = pytest.session.get_standing_orders()
    assert response == []


# TODO: check response API
def test_remove_pin():
    response = pytest.session.remove_pin(pytest.access_id)
    assert response is not None


def test_delete_account():
    response = pytest.session.remove_account(pytest.account_id)
    assert response is None


def test_remove_user():
    response = pytest.session.remove_user()
    assert response == {}
