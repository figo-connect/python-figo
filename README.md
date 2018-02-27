# python-figo [![Build Status](https://img.shields.io/travis/figo-connect/python-figo.svg?style=flat-square)](https://travis-ci.org/figo-connect/python-figo) [![PyPi Version](http://img.shields.io/pypi/v/python-figo.svg?style=flat-square)](https://pypi.python.org/pypi/python-figo) [![Code Coverage](https://img.shields.io/codecov/c/github/figo-connect/python-figo.svg?style=flat-square)](https://codecov.io/github/figo-connect/python-figo)

Python bindings for the figo Connect API: http://docs.figo.io/v3/

# Usage

First, you have to install the package:

```shell
pip install python-figo
```

Now you can create a new session from the demo access token and read data:

```python
from figo import FigoSession

session = FigoSession("ASHWLIkouP2O6_bgA2wWReRhletgWKHYjLqDaqb0LFfamim9RjexTo22ujRIP_cjLiRiSyQXyt2kM1eXU2XLFZQ0Hro15HikJQT_eNeT_9XQ")

# Print out a list of accounts including its balance
for account in session.accounts:
    print account
    print account.balance

# Print out the list of all transactions on a specific account
for transaction in session.get_account("A1.2").transactions:
    print transaction
```

It is just as simple to allow users to login through the API:

```python
import webbrowser
from figo import FigoConnection, FigoSession

connection = FigoConnection("<client ID>", "<client secret>", "http://my-domain.org/redirect-url")

def start_login():
    # open the webbrowser to kick off the login process
    webbrowser.open(connection.login_url(scope="accounts=ro transactions=ro", state="qweqwe"))

def process_redirect(authentication_code, state):
    # handle the redirect url invocation, which gets passed an authentication code and the state (from the initial login_url call)

    # authenticate the call
    if state != "qweqwe":
        raise Exception("Bogus redirect, wrong state")

    # trade in authentication code for access token
    token_dict = connection.convert_authentication_code(authentication_code)

    # start session
    session = FigoSession(token_dict["access_token"])

    # access data
    for account in session.accounts:
        print account.name
```

You can find more documentation at http://python-figo.readthedocs.org

# Demos

In this repository you can also have a look at a simple console (`console_demo.py`) and web demo (`web_demo`). While the console demo simply accesses the figo API, the web demo implements the full OAuth flow.

To install dependencies for the web demo, use

```shell
pip install python-figo[webdemo]
```

# Environment variables

- `FIGO_SSL_FINGERPRINT`
  - Override the default fingerprints with a comma seperated list of fingerprints.
- `FIGO_API_ENDPOINT`
  - Override the default API endpoint by setting the environment variable.
- `FIGO_CLIENT_ID`, `FIGO_CLIENT_SECRET`
  - Override to run tests with a client other than the demo client
  
