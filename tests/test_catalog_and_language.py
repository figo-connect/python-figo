import pytest

from figo import FigoException
from figo import FigoSession
from figo.models import Service
from figo.models import LoginSettings

CREDENTIALS = ["figo", "figo"]
BANK_CODE = "90090042"
CLIENT_ERROR = 1000


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
