import uuid
from logging import basicConfig
import os

import pytest

from figo.figo import FigoConnection, FigoSession

basicConfig(level='DEBUG')

DEMO_CREDENTIALS = {
    'client_id': 'C-9rtYgOP3mjHhw0qu6Tx9fgk9JfZGmbMqn-rnDZnZwI',
    'client_secret': 'Sv9-vNfocFiTe_NoMRkvNLe_jRRFeESHo8A0Uhyp7e28',
    'api_endpoint': 'https://api.figo.me',
    'ssl_fingerprint': ('79:B2:A2:93:00:85:3B:06:92:B1:B5:F2:24:79:48:58:3A:A5:22:0F:C5:CD:E9:49:9A:C8:45:1E:DB:E0:DA'
                        ':50'),
}

CREDENTIALS = {
    'client_id': os.getenv('FIGO_CLIENT_ID', DEMO_CREDENTIALS['client_id']),
    'client_secret': os.getenv('FIGO_CLIENT_SECRET', DEMO_CREDENTIALS['client_secret']),
    'api_endpoint': os.getenv('FIGO_API_ENDPOINT', DEMO_CREDENTIALS['api_endpoint']),
    'ssl_fingerprint': os.getenv('FIGO_SSL_FINGERPRINT', DEMO_CREDENTIALS['ssl_fingerprint']),
}

PASSWORD = 'some_words'

DEMO_TOKEN = ('ASHWLIkouP2O6_bgA2wWReRhletgWKHYjLqDaqb0LFfamim9RjexT'
              'o22ujRIP_cjLiRiSyQXyt2kM1eXU2XLFZQ0Hro15HikJQT_eNeT_9XQ')


def is_demo(credentials):
    return credentials['client_id'] == DEMO_CREDENTIALS['client_id']


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
    figo_connection.add_user("Test", new_user_id, PASSWORD)
    response = figo_connection.credential_login(new_user_id, PASSWORD)

    scope = response['scope']

    required_scopes = [
        'accounts=rw',
        'transactions=rw',
        'user=rw',
        'categorization=rw',
        'create_user',
    ]

    if any(s not in scope for s in required_scopes):
        pytest.skip("The client ID needs write access to the servers.")

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
