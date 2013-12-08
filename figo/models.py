#
#  Created by Stefan Richter on 2013-01-12.
#  Copyright (c) 2013 figo GmbH. All rights reserved.
#


class ModelBase(object):

    @classmethod
    def from_dict(cls, session, data_dict):
        """Creating an instance of the specific type from the data passed in the dictionary `data_dict`"""
        return cls(session, **data_dict)

    def __init__(self, session, **kwargs):
        self.session = session

        for key, value in kwargs.iteritems():
            setattr(self, key, value)


class Account(ModelBase):

    """Object representing one bank account of the user, independent of the exact account type"""

    account_id = None
    """Internal figo Connect account ID"""

    bank_id = None
    """Internal figo Connect bank ID"""

    name = None
    """Account name"""

    owner = None
    """Account owner"""

    auto_sync = None
    """This flag indicates whether the account will be automatically synchronized"""

    account_number = None
    """Account number"""

    bank_code = None
    """Bank code"""

    bank_name = None
    """Bank name"""

    currency = None
    """Three-character currency code"""

    iban = None
    """IBAN"""

    bic = None
    """BIC"""

    type = None
    """Account type: Giro account, Savings account, Credit card, Loan account, PayPal, Cash book or Unknown"""

    icon = None
    """Account icon URL"""

    @property
    def get_balance(self):
        """Balance details of the account, represented by an `AccountBalance` object."""

        return AccountBalance.from_dict(self.session, self.balance)

    @property
    def transactions(self):
        """An array of `Transaction` objects, one for each transaction on the account"""

        return [Transaction.from_dict(self.session, transaction_dict) for transaction_dict in self.session._query_api_with_exception("/rest/accounts/%s/transactions" % (str(self.account_id), ))['transactions']]

    def get_transaction(self, transaction_id):
        """Retrieve a specific transaction.

        :Parameters:
         - `transaction_id` - ID of the transaction to be retrieved

        :Returns:
            a `Transaction` object representing the transaction to be retrieved
        """

        return Transaction.from_dict(self.session, self.session._query_api_with_exception("/rest/accounts/%s/transactions/%s" % (str(self.account_id), str(transaction_id))))

    def __str__(self):
        return "Account: %s (%s at %s)" % (self.name, self.account_number, self.bank_name)


class AccountBalance(ModelBase):

    """Object representing the balance of a certain bank account of the user"""

    balance = None
    """Account balance or None if the balance is not yet known"""

    balance_date = None
    """Bank server timestamp of balance or None if the balance is not yet known."""

    credit_line = None
    """Credit line"""

    monthly_spending_limit = None
    """User-defined spending limit"""

    def __str__(self):
        return "Balance: %d at %s" % (self.balance, str(self.balance_date))


class Transaction(ModelBase):

    """Object representing one bank transaction on a certain bank account of the user"""

    transaction_id = None
    """Internal figo Connect transaction ID"""

    account_id = None
    """Internal figo Connect account ID"""

    name = None
    """Name of originator or recipient"""

    account_number = None
    """Account number of originator or recipient"""

    bank_code = None
    """Bank code of originator or recipient"""

    bank_name = None
    """Bank name of originator or recipient"""

    amount = None
    """Transaction amount"""

    currency = None
    """Three-character currency code"""

    booking_date = None
    """Booking date"""

    value_date = None
    """Value date"""

    purpose = None
    """Purpose text"""

    type = None
    """Transaction type: Transfer, Standing order, Direct debit, Salary or rent, Electronic cash, GeldKarte, ATM, Charges or interest or Unknown"""

    booking_text = None
    """Booking text"""

    booked = None
    """This flag indicates whether the transaction is booked or pending"""

    def __str__(self):
        return "Transaction: %d %s to %s at %s" % (self.amount, self.currency, self.name, str(self.value_date))


class Notification(ModelBase):

    """Object representing a configured notification, e.g a webhook or email hook"""

    notification_id = None
    """Internal figo Connect notification ID from the notification registration response"""

    observe_key = None
    """Notification key: see http://developer.figo.me/#notification_keys"""

    notify_uri = None
    """Notification messages will be sent to this URL"""

    state = None
    """State similiar to sync and logon process. It will passed as POST payload for webhooks"""

    def __str__(self):
        return "Notification: %s triggering %s" % (self.observe_key, self.notify_uri)
