import pytest

from figo import FigoException
from figo.models import (
    Account,
    AccountBalance,
    BankContact,
    Category,
    Challenge,
    Credential,
    LoginSettings,
    Notification,
    Payment,
    PaymentProposal,
    Process,
    ProcessOptions,
    ProcessStep,
    Security,
    Service,
    StandingOrder,
    SynchronizationStatus,
    TaskState,
    TaskToken,
    Transaction,
    User,
)

HTTP_NOT_ACCEPTABLE = 406
CLIENT_ERROR = 1000
ICONS = {
    "48x48": "https://api.figo.me/assets/images/accounts/default-small@2x.png",
    "60x60": "https://api.figo.me/assets/images/accounts/default@2x.png",
}
DEMOBANK_ICON = "https://api.figo.me/assets/images/accounts/demokonto.png"


def test_create_user_from_dict(figo_session):
    data = {
        "email": "demo@figo.me",
        "created_at": "2012-04-19T17:25:54.000Z",
        "language": "en",
        "full_name": "John Doe",
        "id": "U12345",
    }
    user = User.from_dict(figo_session, data)
    assert isinstance(user, User)
    print(user)
    assert user.dump() == {'full_name': 'John Doe', 'language': 'en'}


def test_create_account_from_dict(figo_session):
    data = {
        "account_id": "A1.1",
        "name": "Girokonto",
        "bank_id": "B1.1",
        "owner": "figo",
        "auto_sync": False,
        "account_number": "4711951500",
        "bank_code": "90090042",
        "bank_name": "Demobank",
        "currency": "EUR",
        "iban": "DE67900900424711951500",
        "bic": "DEMODE01",
        "type": "Unknown",
        "icon": "https://api.figo.me/assets/images/accounts/default.png",
        "additional_icons": ICONS,
        "status": {
            "code": -1,
            "message": (
                "Cannot load credential 8f084858-e1c6-4642-87f8-540b530b6e0f: "
                "UUID does not exist."
            ),
            "success_timestamp": "2013-09-11T00:00:00.000Z",
            "sync_timestamp": "2014-07-09T10:04:40.000Z",
        },
        "balance": {
            "balance": 3250.30,
            "balance_date": "2013-09-11T00:00:00.000Z",
            "credit_line": 0.0,
            "monthly_spending_limit": 0.0,
        },
    }
    account = Account.from_dict(figo_session, data)
    assert isinstance(account, Account)
    print(account)


def test_create_bank_contact_from_dict(figo_session):
    data = {
        "bank_id": "B1.1",
        "sepa_creditor_id": "DE67900900424711951500",
        "save_pin": True,
    }
    bank_contact = BankContact.from_dict(figo_session, data)
    assert isinstance(bank_contact, BankContact)
    print(bank_contact)


def test_create_account_balance_from_dict(figo_session):
    data = {
        "balance": 3250.30,
        "balance_date": "2013-09-11T00:00:00.000Z",
        "credit_line": 0.0,
        "monthly_spending_limit": 0.0,
    }
    account_balance = AccountBalance.from_dict(figo_session, data)
    assert isinstance(account_balance, AccountBalance)
    print(account_balance)


def test_create_payment_from_dict(figo_session):
    data = {
        "account_id": "A1.1",
        "account_number": "4711951501",
        "amount": 0.89,
        "bank_additional_icons": ICONS,
        "bank_code": "90090042",
        "bank_icon": DEMOBANK_ICON,
        "creation_timestamp": "2013-07-16T13:53:56.000Z",
        "currency": "EUR",
        "modification_timestamp": "2013-07-16T13:53:56.000Z",
        "name": "figo",
        "notification_recipient": "",
        "payment_id": "P1.1.234",
        "purpose": "Thanks for all the fish.",
        "text_key": 51,
        "text_key_extension": 0,
        "type": "Transfer",
    }
    payment = Payment.from_dict(figo_session, data)
    assert isinstance(payment, Payment)
    print(payment)


def test_create_transaction_from_dict(figo_session):
    data = {
        "account_id": "A1.1",
        "account_number": "4711951501",
        "amount": -17.89,
        "bank_code": "90090042",
        "bank_name": "Demobank",
        "booked": False,
        "booking_date": "2013-04-11T12:00:00.000Z",
        "booking_text": "Ueberweisung",
        "creation_timestamp": "2013-04-11T13:54:02.000Z",
        "currency": "EUR",
        "modification_timestamp": "2013-04-11T13:54:02.000Z",
        "name": "Rogers Shipping, Inc.",
        "purpose": "Ihre Sendung 0815 vom 01.03.2012, Vielen Dank",
        "transaction_id": "T1.1.25",
        "type": "Transfer",
        "value_date": "2013-04-11T12:00:00.000Z",
        "visited": True,
    }
    transaction = Transaction.from_dict(figo_session, data)
    assert isinstance(transaction, Transaction)
    print(transaction)


def test_create_standing_order_from_dict(figo_session):
    data = {
        "account_id": "A12345.6",
        "standing_order_id": "SO12345.6",
        "iban": "DE99012345678910020030",
        "amount": 125.5,
        "currency": "EUR",
        "cents": False,
        "name": "John Doe",
        "purpose": "So long and thanks for all the fish",
        "execution_day": 1,
        "first_execution_date": "2018-08-30T00:00:00.000Z",
        "last_execution_date": "2018-08-30T00:00:00.000Z",
        "interval": "monthly",
        "created_at": "2018-08-30T00:00:00.000Z",
        "modified_at": "2018-08-31T00:00:00.000Z",
    }
    standing_order = StandingOrder.from_dict(figo_session, data)
    assert isinstance(standing_order, StandingOrder)
    print(standing_order)


def test_create_transaction_with_categories(figo_session):
    data = {
        "account_id": "A1.1",
        "account_number": "4711951501",
        "amount": -17.89,
        "bank_code": "90090042",
        "bank_name": "Demobank",
        "booked": False,
        "booking_date": "2013-04-11T12:00:00.000Z",
        "booking_text": "Ueberweisung",
        "creation_timestamp": "2013-04-11T13:54:02.000Z",
        "currency": "EUR",
        "modification_timestamp": "2013-04-11T13:54:02.000Z",
        "name": "Rogers Shipping, Inc.",
        "purpose": "Ihre Sendung 0815 vom 01.03.2012, Vielen Dank",
        "transaction_id": "T1.1.25",
        "type": "Transfer",
        "categories": [
            {"parent_id": None, "id": 150, "name": "Lebenshaltung"},
            {"parent_id": 150, "id": 162, "name": "Spende"},
        ],
        "value_date": "2013-04-11T12:00:00.000Z",
        "visited": True,
    }
    transaction = Transaction.from_dict(figo_session, data)
    assert hasattr(transaction, "categories")
    for category in transaction.categories:
        assert isinstance(category, Category)
        assert hasattr(category, "id")
        print(category)


def test_create_notification_from_dict(figo_session):
    data = {
        "notification_id": "N1.7",
        "notify_uri": "https://api.figo.me/callback",
        "observe_key": "/rest/transactions?include_pending=0",
        "state": "cjLaN3lONdeLJQH3",
    }
    notification = Notification.from_dict(figo_session, data)
    assert isinstance(notification, Notification)
    print(notification)


def test_create_sync_status_from_dict(figo_session):
    data = {
        "code": -1,
        "message": (
            "Cannot load credential 8f084858-e1c6-4642-87f8-540b530b6e0f: "
            "UUID does not exist."
        ),
        "success_timestamp": "2013-09-11T00:00:00.000Z",
        "sync_timestamp": "2014-07-09T10:04:40.000Z",
    }
    sync_status = SynchronizationStatus.from_dict(figo_session, data)
    assert isinstance(sync_status, SynchronizationStatus)
    print(sync_status)


def test_create_service_from_dict(figo_session):
    data = {
        "additional_icons": ICONS,
        "bank_code": "90090042",
        "icon": DEMOBANK_ICON,
        "name": "Demokonto",
        "language": {"available": ["de", "en"], "current": "de"},
    }
    service = Service.from_dict(figo_session, data)
    assert isinstance(service, Service)
    print(service)


def test_create_login_settings_from_dict(figo_session):
    data = {
        "additional_icons": ICONS,
        "advice": "Benutzername: figo, PIN: figo",
        "auth_type": "pin",
        "bank_name": "Demobank",
        "credentials": [
            {"label": "Benutzername"},
            {"label": "PIN", "masked": True},
        ],
        "icon": DEMOBANK_ICON,
        "supported": True,
    }
    login_settings = LoginSettings.from_dict(figo_session, data)
    assert isinstance(login_settings, LoginSettings)
    print(login_settings)


def test_create_credential_from_dict(figo_session):
    data = {"label": "Benutzername"}
    credential = Credential.from_dict(figo_session, data)
    assert isinstance(credential, Credential)
    print(credential)


def test_create_task_token_from_dict(figo_session):
    data = {
        "task_token": (
            "YmB-BtvbWufLnbwgAVfP7XfLatwhrtu0sATfnZNR7LGP-aLXiZ7BKzLdZI--"
            "EqEPnwh_h6mCxToLEBhtA7LVd4uM4gTcZG8F6UJs47g6kWJ0"
        )
    }
    task_token = TaskToken.from_dict(figo_session, data)
    assert isinstance(task_token, TaskToken)
    print(task_token)


def test_create_task_state_from_dict(figo_session):
    data = {
        "account_id": "A1.2",
        "is_ended": False,
        "is_erroneous": False,
        "is_waiting_for_pin": False,
        "is_waiting_for_response": False,
        "message": "Getting balance...",
    }
    task_state = TaskState.from_dict(figo_session, data)
    assert isinstance(task_state, TaskState)
    print(task_state)


def test_create_challenge_from_dict(figo_session):
    data = {
        "title": "Pin Eingabe",
        "label": "pin",
        "format": "Text",
        "data": "dummy",
    }
    challenge = Challenge.from_dict(figo_session, data)
    assert isinstance(challenge, Challenge)
    print(challenge)


def test_create_payment_proposal_from_dict(figo_session):
    data = {
        "account_number": "DE67900900424711951500",
        "bank_code": "DEMODE01",
        "name": "Girokonto",
    }
    payment_proposal = PaymentProposal.from_dict(figo_session, data)
    assert isinstance(payment_proposal, PaymentProposal)
    print(payment_proposal)


def test_create_process_from_dict(figo_session):
    data = {
        "email": "process.1@demo.figo.io",
        "password": "figofigo",
        "state": "123",
        "steps": [
            {"options": {}, "type": "figo.steps.account.create"},
            {
                "options": {
                    "account_number": "100100100",
                    "amount": 99,
                    "bank_code": "82051000",
                    "currency": "EUR",
                    "name": "Figo GmbH",
                    "purpose": "Yearly contribution",
                    "type": "Transfer",
                },
                "type": "figo.steps.payment.submit",
            },
        ],
    }
    process = Process.from_dict(figo_session, data)
    assert isinstance(process, Process)
    print(process)


def test_create_process_step_from_dict(figo_session):
    data = {
        "options": {
            "account_number": "100100100",
            "amount": 99,
            "bank_code": "82051000",
            "currency": "EUR",
            "name": "Figo GmbH",
            "purpose": "Yearly contribution",
            "type": "Transfer",
        },
        "type": "figo.steps.payment.submit",
    }
    process_step = ProcessStep.from_dict(figo_session, data)
    assert isinstance(process_step, ProcessStep)
    print(process_step)


def test_create_process_options_from_dict(figo_session):
    data = {
        "account_number": "100100100",
        "amount": 99,
        "bank_code": "82051000",
        "currency": "EUR",
        "name": "Figo GmbH",
        "purpose": "Yearly contribution",
        "type": "Transfer",
    }
    process_options = ProcessOptions.from_dict(figo_session, data)
    assert isinstance(process_options, ProcessOptions)
    print(process_options)


def test_create_process_token_from_dict(figo_session):
    data = {
        "task_token": (
            "YmB-BtvbWufLnbwgAVfP7XfLatwhrtu0sATfnZNR7LGP-aLXiZ7BKzLdZI--"
            "EqEPnwh_h6mCxToLEBhtA7LVd4uM4gTcZG8F6UJs47g6kWJ0"
        )
    }
    task_token = TaskToken.from_dict(figo_session, data)
    assert isinstance(task_token, TaskToken)
    print(task_token)


def test_create_security_from_dict(figo_session):
    data = {
        "account_id": "A1.4",
        "amount": 32.78,
        "creation_timestamp": "2013-04-10T08:21:36.000Z",
        "isin": "US5949181045",
        "market": "Frankfurt",
        "modification_timestamp": "2013-04-11T13:54:02.000Z",
        "name": "MICROSOFT DL-,00000625",
        "price": 32.79,
        "purchase_price": 38.96,
        "quantity": 1,
        "security_id": "S1.1",
        "trade_timestamp": "2014-07-29 15:00:00",
    }
    security = Security.from_dict(figo_session, data)
    assert isinstance(security, Security)
    print(security)


OLD_ERROR_FORMAT = {
    "error": {
        "code": None,
        "data": {},
        "description": None,
        "group": "unknown",
        "message": "Unsupported language",
        "name": "Not Acceptable",
    },
    "status": HTTP_NOT_ACCEPTABLE,
}
NEW_ERROR_FORMAT = {
    "error": {
        "code": CLIENT_ERROR,
        "data": {},
        "description": "Unsupported language",
        "group": "client",
    },
    "status": HTTP_NOT_ACCEPTABLE,
}


@pytest.mark.parametrize("payload", [OLD_ERROR_FORMAT, NEW_ERROR_FORMAT])
def test_create_figo_exception_from_dict(payload):
    exc = FigoException.from_dict(payload)
    assert isinstance(exc, FigoException)
    print(exc)
