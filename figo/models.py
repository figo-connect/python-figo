#
#  Created by Stefan Richter on 2013-01-12.
#  Copyright (c) 2013 figo GmbH. All rights reserved.
#

import dateutil.parser


class ModelBase(object):
    __dump_attributes__ = []

    @classmethod
    def from_dict(cls, session, data_dict):
        """Creating an instance of the specific type from the data passed in the dictionary `data_dict`"""
        return cls(session, **data_dict)

    def __init__(self, session, **kwargs):
        self.session = session

        for key, value in kwargs.items():
            setattr(self, key, value)

    def dump(self):
        result = {}
        for attribute in self.__dump_attributes__:
            value = getattr(self, attribute)
            if value is not None:
                result[attribute] = value
        return result


class Account(ModelBase):
    """Object representing one bank account of the user, independent of the exact account type"""

    __dump_attributes__ = ["name", "owner", "auto_sync"]

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

    additional_icons = None
    """Account icon in other resolutions"""

    status = None
    """Synchronization status object"""

    @property
    def bank(self):
        """The corresponding BankContact object for this account"""
        return self.session.get_bank(self.bank_id)

    @property
    def payments(self):
        """An array of `Payment` objects, one for each transaction on the account"""
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

    def get_transactions(self, since=None, count=1000, offset=0, include_pending=False):
        """Get an array of `Transaction` objects, one for each transaction of the user

        :Parameters:
         - `since` - this parameter can either be a transaction ID or a date
         - `count` - limit the number of returned transactions
         - `offset` - which offset into the result set should be used to determin the first transaction to return (useful in combination with count)
         - `include_pending` - this flag indicates whether pending transactions should be included in the response; pending transactions are always included as a complete set, regardless of the `since` parameter

        :Returns:
            `List` of Transaction objects
        """
        return self.session.get_transactions(self.account_id, since, count, offset, include_pending)

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
        if self.status:
            self.status = SynchronizationStatus.from_dict(self.session, self.status)
        if self.balance:
            self.balance = AccountBalance.from_dict(self.session, self.balance)


class BankContact(ModelBase):
    """Object representing a BankContact"""

    __dump_attributes__ = ["sepa_creditor_id"]

    bank_id = None
    """Internal figo Connect bank ID"""

    sepa_creditor_id = None
    """SEPA direct debit creditor ID."""

    save_pin = None
    """This flag indicates whether the user has chosen to save the PIN on the figo Connect server."""

    def __str__(self):
        return "BankContact: %s " % self.bank_id


class AccountBalance(ModelBase):
    """Object representing the balance of a certain bank account of the user"""

    __dump_attributes__ = ["credit_line", "monthly_spending_limit"]

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
        if self.status:
            self.status = SynchronizationStatus.from_dict(self.session, self.status)

        if self.balance_date:
            self.balance_date = dateutil.parser.parse(self.balance_date)


class Payment(ModelBase):
    """Object representing a Payment"""

    __dump_attributes__ = ["type", "name", "account_number", "bank_code", "amount", "currency", "purpose"]

    payment_id = None
    """Internal figo Connect payment ID"""

    account_id = None
    """Internal figo Connect account ID"""

    type = None
    """Payment type"""

    name = None
    """Name of creditor or debtor"""

    account_number = None
    """Account number of creditor or debtor"""

    bank_code = None
    """Bank code of creditor or debtor"""

    bank_name = None
    """Bank name of creditor or debtor"""

    bank_icon = None
    """Icon of creditor or debtor bank"""

    bank_additional_icons = None
    """Icon of the creditor or debtor bank in other resolutions"""

    amount = None
    """Order amount"""

    currency = None
    """Three-character currency code"""

    purpose = None
    """Purpose text"""

    submission_timestamp = None
    """Timestamp of submission to the bank server."""

    creation_timestamp = None
    """Internal creation timestamp on the figo Connect server."""

    modification_timestamp = None
    """Internal modification timestamp on the figo Connect server."""

    transaction_id = None
    """Transaction ID. This field is only set if the payment has been matched to a transaction."""

    def __init__(self, session, **kwargs):
        super(Payment, self).__init__(session, **kwargs)

        if self.submission_timestamp:
            self.submission_timestamp = dateutil.parser.parse(self.submission_timestamp)

        if self.creation_timestamp:
            self.creation_timestamp = dateutil.parser.parse(self.creation_timestamp)

        if self.modification_timestamp:
            self.modification_timestamp = dateutil.parser.parse(self.modification_timestamp)

    def __str__(self):
        return "Payment: %s (%s at %s)" % (self.name, self.account_number, self.bank_name)


class Transaction(ModelBase):
    """Object representing one bank transaction on a certain bank account of the user"""

    __dump_attributes__ = []

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
            self.creation_timestamp = dateutil.parser.parse(self.creation_timestamp)

        if self.modification_timestamp:
            self.modification_timestamp = dateutil.parser.parse(self.modification_timestamp)

        if self.booking_date:
            self.booking_date = dateutil.parser.parse(self.booking_date)

        if self.value_date:
            self.value_date = dateutil.parser.parse(self.value_date)

    def __str__(self):
        return "Transaction: %d %s to %s at %s" % (self.amount, self.currency, self.name, str(self.value_date))


class Notification(ModelBase):
    """Object representing a configured notification, e.g a webhook or email hook"""

    __dump_attributes__ = ["observe_key", "notify_uri", "state"]

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

    __dump_attributes__ = []

    code = None
    """Internal figo Connect status code"""

    message = None
    """Human-readable error message"""

    sync_timestamp = None
    """Timestamp of last synchronization"""

    success_timestamp = None
    """Timestamp of last successful synchronization"""

    def __str__(self):
        return "Synchronization Status: %s (%s)" % (self.code, self.message)


class User(ModelBase):
    """Object representing an user"""

    __dump_attributes__ = ["name", "address", "send_newsletter", "language"]

    user_id = None
    """Internal figo Connect user ID."""

    name = None
    """First and last name."""

    email = None
    """Email address."""

    address = None
    """Postal address for bills, etc."""

    verified_email = None
    """This flag indicates whether the email address has been verified."""

    send_newsletter = None
    """This flag indicates whether the user has agreed to be contacted by email."""

    language = None
    """Two-letter code of preferred language."""

    premium = None
    """This flag indicates whether the figo Account plan is free or premium."""

    premium_expires_on = None
    """Timestamp of premium figo Account expiry."""

    premium_subscription = None
    """Provider for premium subscription or Null of no subscription is active."""

    join_date = None
    """Timestamp of figo Account registration."""

    def __init__(self, session, **kwargs):
        super(User, self).__init__(session, **kwargs)

        if self.join_date:
            self.join_date = dateutil.parser.parse(self.join_date)

    def __str__(self):
        return "User: %s (%s, %s)" % (self.name, self.user_id, self.email)


class WebhookNotification(ModelBase):
    """Object representing a WebhookNotification"""

    __dump_attributes__ = []

    notification_id = None
    """Internal figo Connect notification ID from the notification registration response."""

    observe_key = None
    """The Notification key"""

    state = None
    """The state parameter from the notification registration request."""

    data = None
    """Object or List with the data (`AccountBalance` or `Transaction`)"""

    def __str__(self):
        return "WebhookNotification: %s" % (self.notification_id)
