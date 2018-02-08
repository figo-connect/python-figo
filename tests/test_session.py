from __future__ import unicode_literals

import platform

import pytest

from figo import FigoException
from figo.models import Notification
from figo.models import Payment
from figo.models import TaskToken


def test_get_account(figo_session, account_ids):
    account_id = account_ids[0]
    account = figo_session.get_account(account_id)
    assert account.account_id == account_id


def test_get_account_tan_schemes(figo_session, giro_account):
    account = figo_session.get_account(giro_account.account_id)
    assert len(account.supported_tan_schemes) > 0


def test_get_account_balance(figo_session, giro_account):
    # account sub-resources
    balance = figo_session.get_account_balance(figo_session.get_account(giro_account.account_id))
    assert balance.balance
    assert balance.balance_date


def test_get_account_transactions(figo_session, giro_account):
    transactions = figo_session.get_account(giro_account.account_id).transactions
    assert len(transactions) > 0


def test_get_account_payments(figo_session, giro_account):
    payments = figo_session.get_account(giro_account.account_id).payments
    assert len(payments) >= 0


def test_get_global_transactions(figo_session):
    transactions = figo_session.transactions
    assert len(transactions) > 0


def test_get_global_payments(figo_session):
    payments = figo_session.payments
    assert len(payments) >= 0


def test_get_notifications(figo_session):
    notifications = figo_session.notifications
    assert len(notifications) >= 0


def test_get_missing_account(figo_session):
    with pytest.raises(FigoException):
        figo_session.get_account("A1.22")


def test_error_handling(figo_session):
    with pytest.raises(FigoException):
        figo_session.get_sync_url('qwe', 'qew')


def test_sync_uri(figo_session):
    figo_session.get_sync_url('some_state', 'http://example.com')


def test_get_mail_from_user(figo_session):
    assert figo_session.user.email.endswith("testuser@example.com")


@pytest.mark.skip(reason="race condition on travis")
def test_create_update_delete_notification(figo_session):
    """
    This test sometimes fails, when run for different versions in parallel, e.g. on travis
    It happens because the notification id will always be the same for the demo client.
    This will be solved with running tests against an enhanced sandbox.
    """
    state_version = "V{0}".format(platform.python_version())
    added_notification = figo_session.add_notification(
        Notification.from_dict(figo_session, dict(observe_key="/rest/transactions",
                                                  notify_uri="http://figo.me/test",
                                                  state=state_version)))

    assert added_notification.observe_key == "/rest/transactions"
    assert added_notification.notify_uri == "http://figo.me/test"
    assert added_notification.state == state_version

    print("\n##############")
    print("id: {0}, {1}".format(added_notification.notification_id, added_notification.state))

    added_notification.state = state_version + "_modified"
    modified_notification = figo_session.modify_notification(added_notification)
    assert modified_notification.observe_key == "/rest/transactions"
    assert modified_notification.notify_uri == "http://figo.me/test"
    assert modified_notification.state == state_version + "_modified"

    print("id: {0}, {1}".format(modified_notification.notification_id, modified_notification.state))

    figo_session.remove_notification(modified_notification.notification_id)
    with pytest.raises(FigoException):
        deleted_notification = figo_session.get_notification(modified_notification.notification_id)
        print("id: {0}, {1}".format(
            deleted_notification.notification_id, deleted_notification.state))
        print("#"*10)


def test_create_update_delete_payment(figo_session, giro_account):
    added_payment = figo_session.add_payment(
        Payment.from_dict(figo_session, dict(account_id=giro_account.account_id,
                                             type="Transfer",
                                             account_number="4711951501",
                                             bank_code="90090042",
                                             name="figo",
                                             purpose="Thanks for all the fish.",
                                             amount=0.89)))

    assert added_payment.account_id, giro_account.account_id
    assert added_payment.bank_name == "Demobank"
    assert added_payment.amount == 0.89

    added_payment.amount = 2.39
    modified_payment = figo_session.modify_payment(added_payment)
    assert modified_payment.payment_id == added_payment.payment_id
    assert modified_payment.account_id == giro_account.account_id
    assert modified_payment.bank_name == "Demobank"
    assert modified_payment.amount == 2.39

    figo_session.remove_payment(modified_payment)
    with pytest.raises(FigoException):
        figo_session.get_payment(modified_payment.account_id, modified_payment.payment_id)


def test_delete_transaction(figo_session, giro_account):
    transaction = giro_account.transactions[0]
    figo_session.delete_transaction(giro_account.account_id, transaction.transaction_id)


def test_get_payment_proposals(figo_session):
    proposals = figo_session.get_payment_proposals()
    assert len(proposals) >= 1


def test_start_task(figo_session):
    # Valid task token needed
    task_token = TaskToken(figo_session)
    task_token.task_token = "invalidTaskToken"
    with pytest.raises(FigoException):
        figo_session.start_task(task_token)


def test_poll_task_state(figo_session):
    # Valid task token needed
    task_token = TaskToken(figo_session)
    task_token.task_token = "invalidTaskToken"
    with pytest.raises(FigoException):
        figo_session.get_task_state(task_token)


def test_cancel_task(figo_session):
    # Valid task token needed
    task_token = TaskToken(figo_session)
    task_token.task_token = "invalidTaskToken"
    with pytest.raises(FigoException):
        figo_session.cancel_task(task_token)


def test_sync_account(figo_session):
    assert figo_session.sync_account(state="qweqwe")


def test_get_bank(figo_session, giro_account):

    bank = figo_session.get_bank(giro_account.bank_id)
    assert bank.bank_id
