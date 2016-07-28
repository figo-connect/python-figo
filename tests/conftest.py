import uuid
from logging import basicConfig

basicConfig(level='DEBUG')

import pytest

from figo.figo import FigoConnection, FigoSession

CLIENT_ID = "C-9rtYgOP3mjHhw0qu6Tx9fgk9JfZGmbMqn-rnDZnZwI"
CLIENT_SECRET = "Sv9-vNfocFiTe_NoMRkvNLe_jRRFeESHo8A0Uhyp7e28"
USER = "{0}testuser@example.com".format(uuid.uuid4())
PASSWORD = "some_words"

DEMO_TOKEN = "ASHWLIkouP2O6_bgA2wWReRhletgWKHYjLqDaqb0LFfamim9RjexTo22ujRIP_cjLiRiSyQXyt2kM1eXU2XLFZQ0Hro15HikJQT_eNeT_9XQ"


@pytest.fixture
def figo_connection():
    return FigoConnection(CLIENT_ID, CLIENT_SECRET, "https://127.0.0.1/")


@pytest.yield_fixture
def figo_session(figo_connection):
    figo_connection.add_user("Test", USER, PASSWORD)
    response = figo_connection.credential_login(USER, PASSWORD)
    session = FigoSession(response["access_token"])

    yield session

    session.remove_user()


@pytest.fixture
def demo_session():
    return FigoSession(DEMO_TOKEN)
