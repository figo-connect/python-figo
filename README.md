python-figo [![Build Status](https://travis-ci.org/figo-connect/python-figo.png)](https://travis-ci.org/figo-connect/python-figo)
===========

Python bindings for the figo connect API: http://figo.me

Simply install them with pip:

```bash
pip install python-figo
```

And just as easy to use:
```python
from figo import FigoSession

session = FigoSession("ASHWLIkouP2O6_bgA2wWReRhletgWKHYjLqDaqb0LFfamim9RjexTo22ujRIP_cjLiRiSyQXyt2kM1eXU2XLFZQ0Hro15HikJQT_eNeT_9XQ")

# print out a list of accounts including its balance
for account in session.accounts:
    print account
    print account.balance

# print out the list of all transactions on a specific account
for transaction in session.get_account("A1.2").transactions:
    print transaction
```

You can find more documentation at http://python-figo.readthedocs.org
