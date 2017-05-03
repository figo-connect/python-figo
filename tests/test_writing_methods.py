import time
from uuid import uuid4

import pytest

from figo.figo import FigoPinException
from figo.models import TaskToken, TaskState, Service, LoginSettings

CREDENTIALS = ["figo", "figo"]
BANK_CODE = "90090042"


def test_03_get_supported_payment_services(figo_session):
    services = figo_session.get_supported_payment_services("de")
    assert len(services) == 27
    assert isinstance(services[0], Service)


def test_04_get_login_settings(figo_session):
    login_settings = figo_session.get_login_settings("de", BANK_CODE)
    assert isinstance(login_settings, LoginSettings)


def t_05_add_account(figo_session):
    token = figo_session.add_account("de", CREDENTIALS, BANK_CODE)
    assert isinstance(token, TaskToken)
    task_state = figo_session.get_task_state(token)
    time.sleep(5)
    assert isinstance(task_state, TaskState)
    assert len(figo_session.accounts) == 1


def test_050_add_account_and_sync_wrong_pin(figo_session):
    wrong_credentials = [CREDENTIALS[0], "123456"]
    with pytest.raises(FigoPinException):
        figo_session.add_account_and_sync("de", wrong_credentials, BANK_CODE)
    assert len(figo_session.accounts) == 0


def test_051_add_account_and_sync_wrong_and_correct_pin(figo_session):
    wrong_credentials = [CREDENTIALS[0], "123456"]
    figo_session.sync_poll_retry = 100
    try:
        task_state = figo_session.add_account_and_sync("de", wrong_credentials, BANK_CODE)
    except FigoPinException as pin_exception:
        task_state = figo_session.add_account_and_sync_with_new_pin(pin_exception, CREDENTIALS[1])
    time.sleep(5)
    assert isinstance(task_state, TaskState)
    assert len(figo_session.accounts) == 3


@pytest.mark.skip(reason="test expects state of account, that are not prepared at the moment")
def test_06_modify_transaction(figo_session):
    account = figo_session.accounts[0]
    transaction = account.transactions[0]
    response = figo_session.modify_transaction(
        account.account_id,
        transaction.transaction_id,
        visited=False)

    assert not response.visited
    response = figo_session.modify_transaction(
        account.account_id,
        transaction.transaction_id,
        visited=True)

    assert response.visited


@pytest.mark.skip(reason="test expects state of account, that are not prepared at the moment")
def test_07_modify_account_transactions(figo_session):
    account = figo_session.accounts[0]
    figo_session.modify_account_transactions(account.account_id, False)

    assert not any([transaction.visited for transaction in account.transactions])
    figo_session.modify_account_transactions(account.account_id, True)
    assert all([transaction.visited for transaction in account.transactions])


@pytest.mark.skip(reason="test expects state of account, that are not prepared at the moment")
def test_08_modify_user_transactions(figo_session):
    figo_session.modify_user_transactions(False)
    assert not any([transaction.visited for transaction in figo_session.transactions])

    figo_session.modify_user_transactions(True)
    assert all([transaction.visited for transaction in figo_session.transactions])


@pytest.mark.skip(reason="test expects state of account, that are not prepared at the moment")
def test_09_delete_transaction(figo_session):
    account = figo_session.accounts[0]
    transaction = account.transactions[0]
    transaction_count = len(account.transactions)
    figo_session.delete_transaction(account.account_id, transaction.transaction_id)
    assert transaction_count - 1 == account.transactions
