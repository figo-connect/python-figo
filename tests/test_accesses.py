import pytest

from figo import FigoSession

CREDENTIALS = { "account_number" : "foobarbaz", "pin" : "12345" }
CONSENT = { "recurring": True, "period": 90, "scopes": ["ACCOUNTS", "BALANCES", "TRANSACTIONS"], "accounts": [{ "id": "DE67900900424711951500", "currency": "EUR" }] }
ACCESS_METHOD_ID = "ae441170-b726-460c-af3c-b76756de00e0"
data = {}

def test_add_access(access_token):
  figo_session = FigoSession(access_token)
  ACCESS_METHOD_ID = "ae441170-b726-460c-af3c-b76756de00e0"
  response = figo_session.add_access(ACCESS_METHOD_ID,CREDENTIALS,CONSENT)
  data["access_id"] = response["id"]
  assert response.has_key("id") == True
  return data

# def test_add_access_with_wrong_access_id(access_token):
#   figo_session = FigoSession(access_token)
#   access_method_id = "pipo"
#   response = figo_session.add_access(access_method_id,CREDENTIALS,CONSENT)
#   assert response.has_key("error") == True

# def test_get_accesses(access_token):
#   figo_session = FigoSession(access_token)
#   accesses = figo_session.get_accesses()
#   assert len(accesses) > 0

def test_add_sync(access_token):
  figo_session = FigoSession(access_token)
  response = figo_session.add_sync(data["access_id"], None, None, None, None, None)
  #TODO: Add error and challenge in the response!!!
  print "RESPONSE", response
  # print response["challenge"]
  data["sync_id"] = response["id"]
  # data["challenge_id"] = response["challenge"]["id"]
  assert response["status"] == 'QUEUED'
  return data

def test_get_sync(access_token):
  figo_session = FigoSession(access_token)
  response = figo_session.get_sync(data["access_id"], data["sync_id"])
  print response
  assert response["id"] == data["sync_id"]
  assert response["status"] == "RUNNING"
  assert 1 == 2

# def test_solve_synchronization_challenge(access_token):
#   payload = { "value": "111111" }
#   figo_session = FigoSession(access_token)
#   response = figo_session.solve_synchronization_challenge(data["access_id"], data["sync_id"], data["challenge_id"], payload)
#   assert 1 == 2