from figo.models import Account
from figo.models import AccountBalance
from figo.models import BankContact
from figo.models import Category
from figo.models import Challenge
from figo.models import Credential
from figo.models import LoginSettings
from figo.models import Notification
from figo.models import Payment
from figo.models import PaymentProposal
from figo.models import Process
from figo.models import ProcessOptions
from figo.models import ProcessStep
from figo.models import Security
from figo.models import Service
from figo.models import SynchronizationStatus
from figo.models import TaskState
from figo.models import TaskToken
from figo.models import Transaction
from figo.models import User


def test_create_account_from_dict(demo_session):
    data = {"account_id": "A1.1",
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
            "additional_icons": {
                "48x48": "https://api.figo.me/assets/images/accounts/default-small@2x.png",
                "60x60": "https://api.figo.me/assets/images/accounts/default@2x.png"},
            "status": {
                "code": -1,
                "message": "Cannot load credential 8f084858-e1c6-4642-87f8-540b530b6e0f: "
                           "UUID does not exist.",
                "success_timestamp": "2013-09-11T00:00:00.000Z",
                "sync_timestamp": "2014-07-09T10:04:40.000Z"},
            "balance": {
                "balance": 3250.30,
                "balance_date": "2013-09-11T00:00:00.000Z",
                "credit_line": 0.0,
                "monthly_spending_limit": 0.0
            }
            }
    account = Account.from_dict(demo_session, data)
    assert isinstance(account, Account)


def test_create_bank_contact_from_dict(demo_session):
    data = {"bank_id": "B1.1",
            "sepa_creditor_id": "DE67900900424711951500",
            "save_pin": True}
    bank_contact = BankContact.from_dict(demo_session, data)
    assert isinstance(bank_contact, BankContact)


def test_create_account_balance_from_dict(demo_session):
    data = {
        "balance": 3250.30,
        "balance_date": "2013-09-11T00:00:00.000Z",
        "credit_line": 0.0,
        "monthly_spending_limit": 0.0
    }
    account_balance = AccountBalance.from_dict(demo_session, data)
    assert isinstance(account_balance, AccountBalance)


def test_create_payment_from_dict(demo_session):
    data = {
        "account_id": "A1.1",
        "account_number": "4711951501",
        "amount": 0.89,
        "bank_additional_icons": {
            "48x48": "https://api.figo.me/assets/images/accounts/default-small@2x.png",
            "60x60": "https://api.figo.me/assets/images/accounts/default@2x.png"
        },
        "bank_code": "90090042",
        "bank_icon": "https://api.figo.me/assets/images/accounts/demokonto.png",
        "creation_timestamp": "2013-07-16T13:53:56.000Z",
        "currency": "EUR",
        "modification_timestamp": "2013-07-16T13:53:56.000Z",
        "name": "figo",
        "notification_recipient": "",
        "payment_id": "P1.1.234",
        "purpose": "Thanks for all the fish.",
        "text_key": 51,
        "text_key_extension": 0,
        "type": "Transfer"
    }
    payment = Payment.from_dict(demo_session, data)
    assert isinstance(payment, Payment)


def test_create_transaction_from_dict(demo_session):
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
        "visited": True
    }
    transaction = Transaction.from_dict(demo_session, data)
    assert isinstance(transaction, Transaction)


def test_create_transaction_with_categories(demo_session):
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
            {
                "parent_id": None,
                "id": 150,
                "name": "Lebenshaltung"
            },
            {
                "parent_id": 150,
                "id": 162,
                "name": "Spende"
            }
        ],
        "value_date": "2013-04-11T12:00:00.000Z",
        "visited": True
    }
    transaction = Transaction.from_dict(demo_session, data)
    assert hasattr(transaction, 'categories')
    for category in transaction.categories:
        assert isinstance(category, Category)
        assert hasattr(category, 'id')


def test_create_notification_from_dict(demo_session):
    data = {
        "notification_id": "N1.7",
        "notify_uri": "https://api.figo.me/callback",
        "observe_key": "/rest/transactions?include_pending=0",
        "state": "cjLaN3lONdeLJQH3"
    }
    notification = Notification.from_dict(demo_session, data)
    assert isinstance(notification, Notification)


def test_create_sync_status_from_dict(demo_session):
    data = {
        "code": -1,
        "message": "Cannot load credential 8f084858-e1c6-4642-87f8-540b530b6e0f: "
                   "UUID does not exist.",
        "success_timestamp": "2013-09-11T00:00:00.000Z",
        "sync_timestamp": "2014-07-09T10:04:40.000Z"
    }
    sync_status = SynchronizationStatus.from_dict(demo_session, data)
    assert isinstance(sync_status, SynchronizationStatus)


def test_create_user_from_dict(demo_session):
    data = {
        "address": {
            "city": "Berlin",
            "company": "figo",
            "postal_code": "10969",
            "street": "Ritterstr. 2-3"
        },
        "email": "demo@figo.me",
        "join_date": "2012-04-19T17:25:54.000Z",
        "language": "en",
        "name": "John Doe",
        "premium": True,
        "premium_expires_on": "2014-04-19T17:25:54.000Z",
        "premium_subscription": "paymill",
        "send_newsletter": True,
        "user_id": "U12345",
        "verified_email": True
    }
    user = User.from_dict(demo_session, data)
    assert isinstance(user, User)


def test_create_service_from_dict(demo_session):
    data = {
        "additional_icons": {
            "48x48": "https://api.figo.me/assets/images/accounts/default-small@2x.png",
            "60x60": "https://api.figo.me/assets/images/accounts/default@2x.png"
        },
        "bank_code": "90090042",
        "icon": "https://api.figo.me/assets/images/accounts/demokonto.png",
        "name": "Demokonto"
    }
    service = Service.from_dict(demo_session, data)
    assert isinstance(service, Service)


def test_create_login_settings_from_dict(demo_session):
    data = {
        "additional_icons": {
            "48x48": "https://api.figo.me/assets/images/accounts/default-small@2x.png",
            "60x60": "https://api.figo.me/assets/images/accounts/default@2x.png"
        },
        "advice": "Benutzername: figo, PIN: figo",
        "auth_type": "pin",
        "bank_name": "Demobank",
        "credentials": [
            {
                "label": "Benutzername"
            },
            {
                "label": "PIN",
                "masked": True
            }
        ],
        "icon": "https://api.figo.me/assets/images/accounts/demokonto.png",
        "supported": True
    }
    login_settings = LoginSettings.from_dict(demo_session, data)
    assert isinstance(login_settings, LoginSettings)


def test_create_credential_from_dict(demo_session):
    data = {
        "label": "Benutzername"
    }
    credential = Credential.from_dict(demo_session, data)
    assert isinstance(credential, Credential)


def test_create_task_token_from_dict(demo_session):
    data = {
        "task_token": "YmB-BtvbWufLnbwgAVfP7XfLatwhrtu0sATfnZNR7LGP-aLXiZ7BKzLdZI--EqEPnwh_"
                      "h6mCxToLEBhtA7LVd4uM4gTcZG8F6UJs47g6kWJ0"
    }
    task_token = TaskToken.from_dict(demo_session, data)
    assert isinstance(task_token, TaskToken)


def test_task_token_unicode_logging():
    data = {
        'message': u"\xc3",
        'is_erroneous': False,
        'is_ended': False,
    }
    assert '?' in str(TaskState.from_dict(TaskState, data))


def test_create_task_state_from_dict(demo_session):
    data = {
        "account_id": "A1.2",
        "is_ended": False,
        "is_erroneous": False,
        "is_waiting_for_pin": False,
        "is_waiting_for_response": False,
        "message": "Getting balance..."
    }
    task_state = TaskState.from_dict(demo_session, data)
    assert isinstance(task_state, TaskState)


def test_create_challenge_from_dict(demo_session):
    data = {
        "title": "Pin Eingabe",
        "label": "pin",
        "format": "Text",
        "data": "dummy"
    }
    challenge = Challenge.from_dict(demo_session, data)
    assert isinstance(challenge, Challenge)


def test_create_payment_proposal_from_dict(demo_session):
    data = {
        "account_number": "DE67900900424711951500",
        "bank_code": "DEMODE01",
        "name": "Girokonto"
    }
    payment_proposal = PaymentProposal.from_dict(demo_session, data)
    assert isinstance(payment_proposal, PaymentProposal)


def test_create_process_from_dict(demo_session):
    data = {
        "email": "process.1@demo.figo.io",
        "password": "figofigo",
        "state": "123",
        "steps": [
            {
                "options": {},
                "type": "figo.steps.account.create"
            },
            {
                "options": {
                    "account_number": "100100100",
                    "amount": 99,
                    "bank_code": "82051000",
                    "currency": "EUR",
                    "name": "Figo GmbH",
                    "purpose": "Yearly contribution",
                    "type": "Transfer"
                },
                "type": "figo.steps.payment.submit"
            }
        ]
    }
    process = Process.from_dict(demo_session, data)
    assert isinstance(process, Process)


def test_create_process_step_from_dict(demo_session):
    data = {
        "options": {
            "account_number": "100100100",
            "amount": 99,
            "bank_code": "82051000",
            "currency": "EUR",
            "name": "Figo GmbH",
            "purpose": "Yearly contribution",
            "type": "Transfer"
        },
        "type": "figo.steps.payment.submit"
    }
    process_step = ProcessStep.from_dict(demo_session, data)
    assert isinstance(process_step, ProcessStep)


def test_create_process_options_from_dict(demo_session):
    data = {
        "account_number": "100100100",
        "amount": 99,
        "bank_code": "82051000",
        "currency": "EUR",
        "name": "Figo GmbH",
        "purpose": "Yearly contribution",
        "type": "Transfer"
    }
    process_options = ProcessOptions.from_dict(demo_session, data)
    assert isinstance(process_options, ProcessOptions)


def test_create_process_token_from_dict(demo_session):
    data = {
        "task_token": "YmB-BtvbWufLnbwgAVfP7XfLatwhrtu0sATfnZNR7LGP-aLXiZ7BKzLdZI--EqEPnwh_"
                      "h6mCxToLEBhtA7LVd4uM4gTcZG8F6UJs47g6kWJ0"
    }
    task_token = TaskToken.from_dict(demo_session, data)
    assert isinstance(task_token, TaskToken)


def test_create_security_from_dict(demo_session):
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
        "trade_timestamp": "2014-07-29 15:00:00"
    }
    security = Security.from_dict(demo_session, data)
    assert isinstance(security, Security)
