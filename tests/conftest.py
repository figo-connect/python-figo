import pytest
import uuid

from logging import basicConfig

from figo.credentials import CREDENTIALS
from figo.credentials import DEMO_CREDENTIALS
from figo.credentials import DEMO_TOKEN
from figo.figo import FigoConnection
from figo.figo import FigoSession

basicConfig(level='DEBUG')

PASSWORD = 'some_words'


@pytest.fixture(scope='session')
def figo_connection():
    return FigoConnection(CREDENTIALS['client_id'],
                          CREDENTIALS['client_secret'],
                          "https://127.0.0.1/",
                          api_endpoint=CREDENTIALS['api_endpoint'],
                          fingerprints=CREDENTIALS['ssl_fingerprints'])


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
                       fingerprints=DEMO_CREDENTIALS['ssl_fingerprints'])
