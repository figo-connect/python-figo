import pytest

from figo import FigoSession

CREDENTIALS = { "account_number" : "foobarbaz", "pin" : "12345" }
CONSENT = { "recurring": True, "period": 90, "scopes": ["ACCOUNTS", "BALANCES", "TRANSACTIONS"], "accounts": [{ "id": "DE67900900424711951500", "currency": "EUR" }] }

def test_add_access(access_token):
    figo_session = FigoSession(access_token)
    access_method_id = "ae441170-b726-460c-af3c-b76756de00e0"
    response = figo_session.add_access(access_method_id,CREDENTIALS,CONSENT)
    assert response.has_key("id") == True

def test_add_access_with_wrong_access_id(access_token):
    figo_session = FigoSession(access_token)
    access_method_id = "pipo"
    response = figo_session.add_access(access_method_id,CREDENTIALS,CONSENT)
    assert response.has_key("error") == True

def test_get_accesses(access_token):
    figo_session = FigoSession(access_token)
    accesses = figo_session.get_accesses()
    assert len(accesses) > 0

