import pytest
import os

from figo import FigoException
from figo import FigoConnection
from figo import FigoSession
from figo.models import Service
from figo.models import LoginSettings
from figo.models import BankContact

from dotenv import load_dotenv
load_dotenv()

API_ENDPOINT = os.getenv("API_ENDPOINT")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

CLIENT_ERROR = 1000
connection  = FigoConnection(CLIENT_ID, CLIENT_SECRET, "https://127.0.0.1/", api_endpoint=API_ENDPOINT)

@pytest.mark.parametrize('language', ['de'])
@pytest.mark.parametrize('country', ['DE', 'AT'])
def test_get_catalog_en_client_auth(language, country):
    catalog = connection.get_catalog(None, country)
    for bank in catalog['banks']:
      assert isinstance(bank, BankContact)
      assert bank.country == country
    for service in catalog['services']:
      assert isinstance(service, Service)

def test_get_catalog_client_auth_query():
    q = 'PayPal'
    catalog = connection.get_catalog(q, None)
    for bank in catalog['banks']:
      assert bank.name == q
    for service in catalog['services']:
      assert service.name == q

@pytest.mark.parametrize('language', ['de'])
@pytest.mark.parametrize('country', ['DE', 'FR'])
def test_get_catalog_en(access_token, language, country):
    figo_session = FigoSession(access_token)
    figo_session.language = language
    catalog = figo_session.get_catalog(country)
    for bank in catalog['banks']:
        assert bank.country == country

def test_get_catalog_invalid_language(access_token):
    figo_session = FigoSession(access_token)
    with pytest.raises(FigoException) as e:
        figo_session.get_catalog("XY")
    assert e.value.code == CLIENT_ERROR

# XXX(Valentin): Catalog needs `accounts=rw`, so it doesn't work with the demo session.
#                Sounds silly at first, but actually there is no point to view the catalog if
#                you can't add accounts.
def test_get_catalog(access_token):
    figo_session = FigoSession(access_token)
    catalog = figo_session.get_catalog()
    assert len(catalog) == 2
