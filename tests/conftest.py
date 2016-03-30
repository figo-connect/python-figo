import pytest
import uuid


from figo.figo import FigoConnection, FigoSession, FigoPinException, FigoException


CLIENT_ID = "C-9rtYgOP3mjHhw0qu6Tx9fgk9JfZGmbMqn-rnDZnZwI"
CLIENT_SECRET = "Sv9-vNfocFiTe_NoMRkvNLe_jRRFeESHo8A0Uhyp7e28"
USER = "{0}testuser@example.com".format(uuid.uuid4())
PASSWORD = "some_words"


@pytest.fixture
def figo_connection():
    return FigoConnection(CLIENT_ID, CLIENT_SECRET, "https://127.0.0.1/")


@pytest.yield_fixture
def figo_session(figo_connection):
    figo_connection.add_user("Test", USER, PASSWORD)
    response = figo_connection.credential_login(USER, PASSWORD)
    assert isinstance(response["access_token"], (str, unicode))
    session = FigoSession(response["access_token"])

    yield session

    session.remove_user()
