import pytest
import uuid
import time

from logging import basicConfig

from figo.credentials import CREDENTIALS
from figo.credentials import DEMO_CREDENTIALS
from figo.credentials import DEMO_TOKEN
from figo import FigoConnection
from figo import FigoSession

basicConfig(level='DEBUG')

PASSWORD = 'some_words'


def new_user_id():
    return "{0}testuser@example.com".format(uuid.uuid4())



def get_figo_connection():
    return FigoConnection(CREDENTIALS['client_id'],
                          CREDENTIALS['client_secret'],
                          "https://127.0.0.1/",
                          api_endpoint=CREDENTIALS['api_endpoint'],
                          fingerprints=CREDENTIALS['ssl_fingerprints'])


@pytest.fixture(scope='module')
def figo_session():
    user_id = new_user_id()
    figo_connection = get_figo_connection()
    figo_connection.add_user("Test", user_id, PASSWORD)
    response = figo_connection.credential_login(user_id, PASSWORD)

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

    task_token = session.add_account("de", ("figo", "figo"), "90090042" )
    state = session.get_task_state(task_token)

    while not state.is_ended:
        state = session.get_task_state(task_token)
        time.sleep(2)
    assert not state.is_erroneous

    yield session

    session.remove_user()


@pytest.fixture(scope='module')
def account_ids(figo_session):

    accs = figo_session.accounts

    yield [a.account_id for a in accs]


@pytest.fixture(scope='module')
def giro_account(figo_session):
    # returns the first account from the demo bank that is of type "Girokonto" and asserts there is at least one
    accs = figo_session.accounts

    giro_accs = [a for a in accs if a.type=="Giro account"]

    assert len(giro_accs) >= 1

    yield giro_accs[0]

@pytest.fixture(scope='module')
def access_token():
    user_id = new_user_id()
    figo_connection = get_figo_connection()
    figo_connection.add_user("Test", user_id, PASSWORD)
    response = figo_connection.credential_login(user_id, PASSWORD)
    access_token = response['access_token']

    yield access_token

    session = FigoSession(access_token)
    session.remove_user()