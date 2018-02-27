import pytest

from figo import FigoException
from figo import FigoSession
from figo.models import Service
from figo.models import LoginSettings

CREDENTIALS = ["figo", "figo"]
BANK_CODE = "90090042"
CLIENT_ERROR = 1000


@pytest.mark.parametrize('language', ['de', 'en'])
def test_get_catalog_en(access_token, language):
    figo_session = FigoSession(access_token)
    figo_session.language = language
    catalog = figo_session.get_catalog()
    for bank in catalog['banks']:
        assert bank.language == language


def test_get_catalog_invalid_language(access_token):
    figo_session = FigoSession(access_token)
    figo_session.language = 'xy'
    with pytest.raises(FigoException) as e:
        figo_session.get_catalog()
    assert e.value.code == CLIENT_ERROR


def test_get_supported_payment_services(access_token):
    figo_session = FigoSession(access_token)
    services = figo_session.get_supported_payment_services("de")
    assert len(services) > 10  # this a changing value, this tests that at least some are returned
    assert isinstance(services[0], Service)


# XXX(Valentin): Catalog needs `accounts=rw`, so it doesn't work with the demo session.
#                Sounds silly at first, but actually there is no point to view the catalog if
#                you can't add accounts.
def test_get_catalog(access_token):
    figo_session = FigoSession(access_token)
    catalog = figo_session.get_catalog()
    assert len(catalog) == 2


def test_get_login_settings(access_token):
    figo_session = FigoSession(access_token)
    login_settings = figo_session.get_login_settings("de", BANK_CODE)
    assert isinstance(login_settings, LoginSettings)
    assert login_settings.advice
    assert login_settings.credentials


def test_set_unset_language(access_token):
    figo_session = FigoSession(access_token)
    assert figo_session.language is None
    figo_session.language = 'de'
    assert figo_session.language == 'de'
    figo_session.language = ''
    assert figo_session.language is None
    figo_session.language = 'de'
