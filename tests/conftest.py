import uuid
from logging import basicConfig
import os

basicConfig(level='DEBUG')

import pytest

from figo.figo import FigoConnection, FigoSession

DEMO_CREDENTIALS = {
    'client_id': 'C-9rtYgOP3mjHhw0qu6Tx9fgk9JfZGmbMqn-rnDZnZwI',
    'client_secret': 'Sv9-vNfocFiTe_NoMRkvNLe_jRRFeESHo8A0Uhyp7e28',
    'api_endpoint': 'https://api.figo.me',
    'ssl_fingerprint': 'DB:E2:E9:15:8F:C9:90:30:84:FE:36:CA:A6:11:38:D8:5A:20:5D:93',
}

CREDENTIALS = {
    'client_id': os.getenv('CLIENT_ID', DEMO_CREDENTIALS['client_id']),
    'client_secret': os.getenv('CLIENT_SECRET', DEMO_CREDENTIALS['client_secret']),
    'api_endpoint': os.getenv('FIGO_API_ENDPOINT', DEMO_CREDENTIALS['api_endpoint']),
    'ssl_fingerprint': os.getenv('FIGO_SSL_FINGERPRINT', DEMO_CREDENTIALS['ssl_fingerprint']),
}

def is_demo(credentials):
    return credentials['client_id'] == DEMO_CREDENTIALS['client_id']

PASSWORD = 'some_words'

DEMO_TOKEN = 'ASHWLIkouP2O6_bgA2wWReRhletgWKHYjLqDaqb0LFfamim9RjexTo22ujRIP_cjLiRiSyQXyt2kM1eXU2XLFZQ0Hro15HikJQT_eNeT_9XQ'

@pytest.fixture(scope='session')
def figo_connection():
    return FigoConnection(CREDENTIALS['client_id'],
                          CREDENTIALS['client_secret'],
                          "https://127.0.0.1/",
                          api_endpoint=CREDENTIALS['api_endpoint'],
                          fingerprints=[CREDENTIALS['ssl_fingerprint']])

@pytest.fixture
def new_user_id():
    return "{0}testuser@example.com".format(uuid.uuid4())

@pytest.yield_fixture
def figo_session(figo_connection, new_user_id):
    if is_demo(CREDENTIALS):
        pytest.skip("The demo client has no write access to the servers.")

    figo_connection.add_user("Test", new_user_id, PASSWORD)
    response = figo_connection.credential_login(new_user_id, PASSWORD)
    session = FigoSession(response['access_token'])

    yield session

    session.remove_user()

@pytest.yield_fixture(scope='module')
def demo_session():
    # TODO(Valentin): we need to run `test_session` (both read-only) against production API
    #                 using demo credentials, since there is no adequate client or data available
    #                 on `staging`. we could:
    #                 - drop these tests entirely and lose quite some code coverage
    #                 - replace by write-then-read tests which cannot be run on external PRs
    #                 - create a non-expiring demo session on `staging`
    return FigoSession(DEMO_TOKEN,
                       api_endpoint=DEMO_CREDENTIALS['api_endpoint'],
                       fingerprints=[DEMO_CREDENTIALS['ssl_fingerprint']])
