..  Sphinx-based documentation file, create HTML documentation using
    sphinx-build -b html . _build

Welcome to figo Python binding documentation!
=============================================

General notes
-------------

*Register application*: Applications that want to access the figo Connect must be registered beforehand. If you’d like to create a partner application, please email us. We will generate a client identifier and client secret for your application.

*Demo Access*: you can use the following access token to test drive figo connect without any risk or needing to even talk to us.

.. code-block:: python
  
  ASHWLIkouP2O6_bgA2wWReRhletgWKHYjLqDaqb0LFfamim9RjexTo22ujRIP_cjLiRiSyQXyt2kM1eXU2XLFZQ0Hro15HikJQT_eNeT_9XQ


Demo Application
----------------

You can easily install the binding using pip:

.. code-block:: bash

    pip install python-figo
    
Retrieving some data is very easy using the demo access from above:

.. code-block:: python

    from figo import FigoSession

    session = FigoSession("ASHWLIkouP2O6_bgA2wWReRhletgWKHYjLqDaqb0LFfamim9RjexTo22ujRIP_cjLiRiSyQXyt2kM1eXU2XLFZQ0Hro15HikJQT_eNeT_9XQ")
    
    # print out a list of accounts including its balance
    for account in session.accounts:
        print(account)
        print(account.balance)

    # print out the list of all transactions on a specific account
    for transaction in session.get_account("A1.2").transactions:
        print(transaction)


It is just as simple to allow users to login through the API:

.. code-block:: python

    import webbrowser
    from figo import FigoConnection, FigoSession

    connection = FigoConnection("<client ID>", "<client secret>", "http://my-domain.org/redirect-url")

    def start_login():
        # open the webbrowser to kick of the login process
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
            print(account.name)


Module Documentation
--------------------
.. automodule:: figo.figo
   :members:

Data Objects
------------
.. automodule:: figo.models
   :members:


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

