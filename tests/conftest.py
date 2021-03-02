import os
import uuid
from logging import basicConfig

import pytest
from dotenv import load_dotenv

from figo import FigoConnection, FigoSession

load_dotenv()

basicConfig(level="DEBUG")

API_ENDPOINT = os.getenv("FIGO_API_ENDPOINT")
CLIENT_ID = os.getenv("FIGO_CLIENT_ID")
CLIENT_SECRET = os.getenv("FIGO_CLIENT_SECRET")
PASSWORD = "some_words"


@pytest.fixture(scope="module")
def new_user_id():
    return "{0}testuser@example.com".format(uuid.uuid4())


@pytest.fixture(scope="module")
def figo_connection():
    return FigoConnection(
        CLIENT_ID,
        CLIENT_SECRET,
        "https://127.0.0.1/",
        api_endpoint=API_ENDPOINT,
    )


@pytest.fixture(scope="module")
def figo_session(figo_connection, new_user_id):
    figo_connection.add_user("Test", new_user_id, PASSWORD)
    response = figo_connection.credential_login(new_user_id, PASSWORD)
    return FigoSession(response["access_token"])


@pytest.fixture(scope="module")
def access_token(figo_connection, new_user_id):
    figo_connection.add_user("Test", new_user_id, PASSWORD)
    response = figo_connection.credential_login(
        new_user_id, PASSWORD, scope="user=rw accounts=rw transactions=rw"
    )
    access_token = response["access_token"]

    yield access_token

    session = FigoSession(access_token)
    session.remove_user()
