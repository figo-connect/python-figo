..  Sphinx-based documentation file, create HTML documentation using
    sphinx-build -b html . _build

Welcome to figo Python binding documentation!
=============================================

General notes
-------------

*Register application*: Applications that want to access the figo Connect must be registered beforehand. If you’d like to create a partner application, please email us. We will generate a client identifier and client secret for your application.

*Demo Access*: you can use the following access token to test drive figo connect without any risk or needing to even talk to us.

.. code::
  
  ASHWLIkouP2O6_bgA2wWReRhletgWKHYjLqDaqb0LFfamim9RjexTo22ujRIP_cjLiRiSyQXyt2kM1eXU2XLFZQ0Hro15HikJQT_eNeT_9XQ


Demo Application
----------------

You can easily install the binding using pip:

.. code::

    pip install python-figo
    
Retrieving some data is very easy using the demo access from above:

.. code:: python

    from figo import FigoSession

    session = FigoSession("ASHWLIkouP2O6_bgA2wWReRhletgWKHYjLqDaqb0LFfamim9RjexTo22ujRIP_cjLiRiSyQXyt2kM1eXU2XLFZQ0Hro15HikJQT_eNeT_9XQ")
    
    # print out a list of accounts including its balance
    for account in session.accounts:
        print account
        print account.balance

    # print out the list of all transactions on a specific account
    for transaction in session.get_account("A1.2").transactions:
        print transaction


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

