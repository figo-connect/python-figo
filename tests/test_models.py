import pytest

# TODO: We need create test case this unused import
from figo.exceptions import FigoException
from figo.models import (  # noqa: F401
    Account,
    AccountBalance,
    Category,
    Challenge,
    Credential,
    LoginSettings,
    Notification,
    Payment,
    Security,
    StandingOrder,
    Sync,
    SynchronizationStatus,
    Transaction,
    User,
    WebhookNotification,
)

HTTP_NOT_ACCEPTABLE = 406
CLIENT_ERROR = 1000
ICONS = {
    "48x48": "https://api.figo.me/assets/images/accounts/default-small@2x.png",
    "60x60": "https://api.figo.me/assets/images/accounts/default@2x.png",
}
ICONS_RES = {
    "48x48": "https://finx-s.finleap.cloud/images/accounts/default_48.png",
    "60x60": "https://finx-s.finleap.cloud/images/accounts/default_60.png",
    "72x72": "https://finx-s.finleap.cloud/images/accounts/default_72.png",
    "84x84": "https://finx-s.finleap.cloud/images/accounts/default_84.png",
    "96x96": "https://finx-s.finleap.cloud/images/accounts/default_96.png",
    "120x120": "https://finx-s.finleap.cloud/images/accounts/default_120.png",
    "144x144": "https://finx-s.finleap.cloud/images/accounts/default_144.png",
    "192x192": "https://finx-s.finleap.cloud/images/accounts/default_192.png",
    "256x256": "https://finx-s.finleap.cloud/images/accounts/default_256.png",
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
        "account_id": "A12345.6",
        "account_number": "0123456789",
        "bank_code": "90090042",
        "iban": "DE99012345678910020030",
        "bic": "DEMOBANKXXX",
        "access_id": "X12345.6",
        "bank_name": "Bank XYZ",
        "icon": {
            "url": "https://finx-s.finleap.cloud/images/accounts/default.png",
            "resolutions": ICONS_RES,
        },
        "currency": "EUR",
        "balance": {
            "balance": 13.37,
            "balance_date": "2018-04-01T00:00:00.000Z",
            "status": {
                "synced_at": "2018-08-30T00:00:00.000Z",
                "succeeded_at": "2018-08-30T00:00:00.000Z",
                "message": "string",
            },
        },
        "type": "Giro account",
        "name": "Giro account",
        "owner": "John Doe",
        "auto_sync": False,
        "save_pin": True,
        "supported_payments": {"SEPA transfer": {}, "SEPA standing order": {}},
        "is_jointly_managed": True,
        "status": {
            "synced_at": "2018-08-30T00:00:00.000Z",
            "succeeded_at": "2018-08-30T00:00:00.000Z",
            "message": "string",
        },
    }
    account = Account.from_dict(figo_session, data)
    assert isinstance(account, Account)
    print(account)


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
