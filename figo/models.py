#
#  Created by Stefan Richter on 2013-01-12.
#  Copyright (c) 2013 figo GmbH. All rights reserved.
#

import datetime


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

    status = None
    """Synchronization status object"""

    @property
    def payments(self):
        """An array of `Transaction` objects, one for each transaction on the account"""
        return self.session.get_payments(self.account_id)

    def get_payment(self, payment_id):
        """Retrieve a specific payment.

        :Parameters:
         - `payment_id` - ID of the payment to be retrieved

        :Returns:
            a `Payment` object representing the payment to be retrieved
        """

        return self.session.get_payments(self.account_id, payment_id)

    @property
    def transactions(self):
        """An array of `Transaction` objects, one for each transaction on the account"""

        return self.session.get_transactions(self.account_id)

    def get_transaction(self, transaction_id):
        """Retrieve a specific transaction.

        :Parameters:
         - `transaction_id` - ID of the transaction to be retrieved

        :Returns:
            a `Transaction` object representing the transaction to be retrieved
        """
        return self.session.get_transaction(self.account_id, transaction_id)

    def __str__(self):
        return "Account: %s (%s at %s)" % (self.name, self.account_number, self.bank_name)

    def __init__(self, session, **kwargs):
        super(Account, self).__init__(session, **kwargs)
        self.status = SynchronizationStatus.from_dict(self.session, self.status)
        self.balance = AccountBalance.from_dict(self.session, self.balance)


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

    status = None
    """Synchronization status object"""

    def __str__(self):
        return "Balance: %d at %s" % (self.balance, str(self.balance_date))

    def __init__(self, session, **kwargs):
        super(AccountBalance, self).__init__(session, **kwargs)
        self.status = SynchronizationStatus.from_dict(self.session, self.status)

        if self.balance_date:
            self.balance_date = datetime.datetime.fromtimestamp(self.balance_date)


class Payment(object):

    """docstring for Payment"""

    payment_id = None
    """Internal figo Connect payment ID"""

    account_id = None
    """ Internal figo Connect account ID"""

    type = None
    """payment type"""

    name = None
    """Name of creditor or debtor"""

    account_number = None
    """Account number or IBAN of creditor or debtor"""

    bank_code = None
    """Bank code or BIC of creditor or debtor"""

    amount = None
    """Order amount"""

    currency = None
    """Three-character currency code"""

    purpose = None
    """Purpose text"""

    text_key = None
    """DTA text key"""

    text_key_extension = None
    """DTA text key extension"""

    notification_recipient = None
    """Recipient of the payment notification (should be an email address)"""

    creation_timestamp = None
    """creation date"""

    modification_timestamp = None
    """modification date"""

    def __init__(self, session, **kwargs):
        super(Payment, self).__init__(session, **kwargs)

        if self.creation_timestamp:
            self.creation_timestamp = datetime.datetime.fromtimestamp(self.creation_timestamp)

        if self.modification_timestamp:
            self.modification_timestamp = datetime.datetime.fromtimestamp(self.modification_timestamp)


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

    creation_timestamp = None
    """creation date"""

    modification_timestamp = None
    """modification date"""

    def __init__(self, session, **kwargs):
        super(Transaction, self).__init__(session, **kwargs)

        if self.creation_timestamp:
            self.creation_timestamp = datetime.datetime.fromtimestamp(self.creation_timestamp)

        if self.modification_timestamp:
            self.modification_timestamp = datetime.datetime.fromtimestamp(self.modification_timestamp)

        if self.booking_date:
            self.booking_date = datetime.datetime.fromtimestamp(self.booking_date)

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


class SynchronizationStatus(ModelBase):

    """Object representing the synchronization status of the figo servers with e banks, payment providers or financial service providers"""

    code = None
    """Internal figo Connect status code"""

    message = None
    """Human-readable error message"""

    sync_timestamp = None
    """Timestamp of last synchronization"""

    success_timestamp = None
    """Timestamp of last successful synchronization"""

    def __str__():
        return "Synchronization Status: %s (%s)" % (self.code, self.message)


class User(ModelBase):

    """Object representing an user"""

    name = None
    """First and last name"""

    email = None
    """Email address"""
