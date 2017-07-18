from __future__ import unicode_literals

import platform

import pytest

from figo.figo import FigoException
from figo.models import Notification
from figo.models import Payment
from figo.models import Process
from figo.models import ProcessToken
from figo.models import TaskToken


def test_get_account(demo_session):
    account = demo_session.get_account("A1.2")
    assert account.account_id == "A1.2"


def test_get_account_tan_schemes(demo_session):
    account = demo_session.get_account("A1.1")
    assert len(account.supported_tan_schemes) == 4


def test_get_account_balance(demo_session):
    # account sub-resources
    balance = demo_session.get_account_balance(demo_session.get_account("A1.2"))
    assert balance.balance
    assert balance.balance_date


def test_get_account_transactions(demo_session):
    transactions = demo_session.get_account("A1.2").transactions
    assert len(transactions) > 0


def test_get_account_payments(demo_session):
    payments = demo_session.get_account("A1.2").payments
    assert len(payments) >= 0


def test_get_global_transactions(demo_session):
    transactions = demo_session.transactions
    assert len(transactions) > 0


def test_get_global_payments(demo_session):
    payments = demo_session.payments
    assert len(payments) >= 0


def test_get_notifications(demo_session):
    notifications = demo_session.notifications
    assert len(notifications) >= 0


def test_get_missing_account(demo_session):
    with pytest.raises(FigoException):
        demo_session.get_account("A1.22")


def test_error_handling(demo_session):
    with pytest.raises(FigoException):
        demo_session.get_sync_url("", "http://localhost:3003/")


def test_sync_uri(demo_session):
    demo_session.get_sync_url("qwe", "qew")


def test_get_mail_from_user(demo_session):
    assert demo_session.user.email == "demo@figo.me"


@pytest.mark.skip(reason="race condition on travis")
def test_create_update_delete_notification(demo_session):
    """
    This test sometimes fails, when run for different versions in parallel, e.g. on travis
    It happens because the notification id will always be the same for the demo client.
    This will be solved with running tests against an enhanced sandbox.
    """
    state_version = "V{0}".format(platform.python_version())
    added_notification = demo_session.add_notification(
        Notification.from_dict(demo_session, dict(observe_key="/rest/transactions",
                                                  notify_uri="http://figo.me/test",
                                                  state=state_version)))

    assert added_notification.observe_key == "/rest/transactions"
    assert added_notification.notify_uri == "http://figo.me/test"
    assert added_notification.state == state_version

    print("\n##############")
    print("id: {0}, {1}".format(added_notification.notification_id, added_notification.state))

    added_notification.state = state_version + "_modified"
    modified_notification = demo_session.modify_notification(added_notification)
    assert modified_notification.observe_key == "/rest/transactions"
    assert modified_notification.notify_uri == "http://figo.me/test"
    assert modified_notification.state == state_version + "_modified"

    print("id: {0}, {1}".format(modified_notification.notification_id, modified_notification.state))

    demo_session.remove_notification(modified_notification.notification_id)
    with pytest.raises(FigoException):
        deleted_notification = demo_session.get_notification(modified_notification.notification_id)
        print("id: {0}, {1}".format(
            deleted_notification.notification_id, deleted_notification.state))
        print("#"*10)


def test_create_update_delete_payment(demo_session):
    added_payment = demo_session.add_payment(
        Payment.from_dict(demo_session, dict(account_id="A1.1",
                                             type="Transfer",
                                             account_number="4711951501",
                                             bank_code="90090042",
                                             name="figo",
                                             purpose="Thanks for all the fish.",
                                             amount=0.89)))

    assert added_payment.account_id, "A1.1"
    assert added_payment.bank_name == "Demobank"
    assert added_payment.amount == 0.89

    added_payment.amount = 2.39
    modified_payment = demo_session.modify_payment(added_payment)
    assert modified_payment.payment_id == added_payment.payment_id
    assert modified_payment.account_id == "A1.1"
    assert modified_payment.bank_name == "Demobank"
    assert modified_payment.amount == 2.39

    demo_session.remove_payment(modified_payment)
    with pytest.raises(FigoException):
        demo_session.get_payment(modified_payment.account_id, modified_payment.payment_id)


def test_set_bank_account_order(demo_session):
    # Access token with accounts=rw needed
    accounts = [demo_session.get_account("A1.2"), demo_session.get_account("A1.1")]
    with pytest.raises(FigoException):
        demo_session.set_account_sort_order(accounts)


def test_get_supported_payment_services(demo_session):
    # Access token with accounts=rw needed
    with pytest.raises(FigoException):
        demo_session.get_supported_payment_services("de")


def test_get_login_settings(demo_session):
    # Access token with accounts=rw needed
    with pytest.raises(FigoException):
        demo_session.get_login_settings("de", "90090042")


def test_setup_new_bank_account(demo_session):
    # Access token with accounts=rw needed
    with pytest.raises(FigoException):
        demo_session.add_account("de", ["figo", "figo"], "90090042")


def test_modify_a_transaction(demo_session):
    # Access token with transactions=rw needed
    with pytest.raises(FigoException):
        demo_session.modify_transaction("A1.1", "T1.24", False)


def test_modify_all_transactions_of_account(demo_session):
    # Access token with transactions=rw needed
    with pytest.raises(FigoException):
        demo_session.modify_account_transactions("A1.1", visited=False)


def test_modify_all_transactions(demo_session):
    # Access token with transactions=rw needed
    with pytest.raises(FigoException):
        demo_session.modify_user_transactions(visited=False)


def test_delete_transaction(demo_session):
    # Access token with transactions=rw needed
    with pytest.raises(FigoException):
        demo_session.delete_transaction("A1.1", "T1.24")


def test_get_payment_proposals(demo_session):
    proposals = demo_session.get_payment_proposals()
    assert len(proposals) == 12


def test_start_task(demo_session):
    # Valid task token needed
    task_token = TaskToken(demo_session)
    task_token.task_token = "invalidTaskToken"
    with pytest.raises(FigoException):
        demo_session.start_task(task_token)


def test_poll_task_state(demo_session):
    # Valid task token needed
    task_token = TaskToken(demo_session)
    task_token.task_token = "invalidTaskToken"
    with pytest.raises(FigoException):
        demo_session.get_task_state(task_token)


def test_cancel_task(demo_session):
    # Valid task token needed
    task_token = TaskToken(demo_session)
    task_token.task_token = "invalidTaskToken"
    with pytest.raises(FigoException):
        demo_session.cancel_task(task_token)


def test_start_process(demo_session):
    # Valid process token needed
    process_token = ProcessToken(demo_session)
    process_token.process_token = "invalidProcessToken"
    with pytest.raises(FigoException):
        demo_session.start_process(process_token)


def test_create_process(demo_session):
    # Access token with process=rw needed
    process = Process(demo_session, email="demo@demo.de", password="figo",
                      state="qwer", steps=["not_valid"])

    with pytest.raises(FigoException):
        demo_session.create_process(process)


def test_sync_account(demo_session):
    assert demo_session.sync_account(state="qweqwe")
