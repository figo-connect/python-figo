# coding:utf-8

import pytest
import time

from mock import patch

from figo.figo import FigoException
from figo.figo import FigoPinException
from figo.models import LoginSettings
from figo.models import Service
from figo.models import TaskState
from figo.models import TaskToken


CREDENTIALS = ["figo", "figo"]
BANK_CODE = "90090042"


def test_03_get_supported_payment_services(figo_session):
    services = figo_session.get_supported_payment_services("de")
    assert len(services) > 10  # this a changing value, this tests that at least some are returned
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
    try:
        with pytest.raises(FigoException):
            figo_session.add_account_and_sync("de", wrong_credentials, BANK_CODE)
        assert len(figo_session.accounts) == 0
    except FigoException as figo_exception:
        # BBB(Valentin): prevent demo account from complaining - it returns no code on error
        if "Please use demo account credentials" not in figo_exception.error_description:
            raise


def test_add_account_and_sync_wrong_pin_postbank(figo_session):
    """
    Check that `FigoPinException` is raised correctly on given task state, which occurs
    when attempting to add an account to Postbank with syntactically correct (9-digit login), but
    invalid credentials. Note that syntactically incorrect credentials return code `20000` and a
    different message.
    """

    mock_task_state = {
        "is_ended": True,
        "account_id": u"A2248267.0",
        "is_waiting_for_pin": False,
        "is_erroneous": True,
        "message": u"Die Anmeldung zum Online-Zugang Ihrer Bank ist fehlgeschlagen. "
                   u"Bitte überprüfen Sie Ihre Benutzerkennung.",
        "error": {
            "code": 10000,
            "group": u"user",
            "name": u"Login credentials are invalid",
            "message": u"9050 Die Nachricht enthält Fehler.; 9800 Dialog abgebrochen; "
                       u"9010 Initialisierung fehlgeschlagen, Auftrag nicht bearbeitet.; "
                       u"3920 Zugelassene Zwei-Schritt-Verfahren für den Benutzer.; "
                       u"9010 PIN/TAN Prüfung fehlgeschlagen; "
                       u"9931 Anmeldename oder PIN ist falsch.",
            "data": {},
            "description": u"Die Anmeldung zum Online-Zugang Ihrer Bank ist fehlgeschlagen. "
                           u"Bitte überprüfen Sie Ihre Benutzerkennung."
        },
        "challenge": {},
        "is_waiting_for_response": False
    }

    with patch.object(figo_session, 'get_task_state') as mock_state:
        with patch.object(figo_session, 'add_account') as mock_account:

            mock_state.return_value = TaskState.from_dict(figo_session, mock_task_state)
            mock_account.return_value = None

            with pytest.raises(FigoPinException) as e:
                figo_session.add_account_and_sync("de", None, None)
            assert e.value.code == 10000
            assert len(figo_session.accounts) == 0


def test_051_add_account_and_sync_wrong_and_correct_pin(figo_session):
    wrong_credentials = [CREDENTIALS[0], "123456"]
    figo_session.sync_poll_retry = 100
    try:
        task_state = figo_session.add_account_and_sync("de", wrong_credentials, BANK_CODE)
    except FigoPinException as pin_exception:
        task_state = figo_session.add_account_and_sync_with_new_pin(pin_exception, CREDENTIALS[1])
        assert isinstance(task_state, TaskState)
        assert len(figo_session.accounts) == 3
    except FigoException as figo_exception:
        # XXXValentin): prevent demo account from complaining
        if figo_exception.code != 90000:
            raise


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
