#
#  Created by Stefan Richter on 2013-01-12.
#  Copyright (c) 2013 figo GmbH. All rights reserved.
#

import dateutil.parser


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


class Bank(ModelBase):

    """Object representing a Bank"""

    bank_name = None
    """Bank name."""

    supported = None
    """This flag indicates whether this bank is supported by figo."""

    credentials = None
    """List of credential objects."""

    auth_type = None
    """If the authentication type is pin, then the user must have the option to save or not to save his or her PIN. If the authentication type is none or token, then there is no such option."""

    advice = None
    """Help text."""

    icon = None
    """Icon URL."""

    def __init__(self, session, **kwargs):
        super(Bank, self).__init__(session, **kwargs)
        if type(self.credentials) is list:
            self.credentials = [Credential.from_dict(self, credential_dict) for credential_dict in self.credentials]

    def __str__(self):
        return "Bank: %s" % (self.bank_name)


class BankContact(ModelBase):

    """Object representing a BankContact"""

    sepa_creditor_id = None
    """SEPA direct debit creditor ID."""

    save_pin = None
    """This flag indicates whether the user has chosen to save the PIN on the figo Connect server."""

    def __str__(self):
        return "BankContact: %s " % self.sepa_creditor_id


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
        if self.status:
            self.status = SynchronizationStatus.from_dict(self.session, self.status)

        if self.balance_date:
            self.balance_date = dateutil.parser.parse(self.balance_date)


class Client(ModelBase):

    """object representing a `Client`"""

    client_id = None
    """Internal figo Connect client ID"""

    name = None
    """Client name"""

    homepage = None
    """Homepage URL"""

    description = None
    """Client description"""

    icon = None
    """Icon URL"""

    scope = None
    """A space delimited set of permissions for the client."""

    valid = None
    """This flag indicates whether the client is still authorized."""

    last_access = None
    """Timestamp of the last request this client made."""

    accounts = None
    """List of account IDs. The client has access to these accounts."""

    def __init__(self, session, **kwargs):
        super(AccountBalance, self).__init__(session, **kwargs)

        if self.last_access:
            self.last_access = dateutil.parser.parse(self.last_access)

        def __str__(self):
            return "Client: %s (%s)" % (self.name, self.homepage)


class Credential(ModelBase):
    label = None
    """Label for text input field"""

    masked = None
    """This indicates whether the this text input field is used for password entry and therefore should be masked."""

    optional = None
    """ This flag indicates whether this text input field is allowed to contain the empty string."""

    def __str__(self):
        return "Credential: %s " % self.label


class Device(ModelBase):

    """Object representing a Device"""

    device_id = None
    """Internal figo Connect device ID"""

    name = None
    """Device name"""

    icon = None
    """Icon URL"""

    last_access = None
    """Timestamp of the last request this device made."""

    def __init__(self, session, **kwargs):
        super(Device, self).__init__(session, **kwargs)

        if self.last_access:
            self.last_access = dateutil.parser.parse(self.last_access)

    def __str__(self):
        return "Device: %s (%s)" % (self.name, self.device_id)


class Payment(ModelBase):

    """Object representing a Payment"""

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
    """ Icon of creditor or debtor bank"""

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

    scheduled_date = None
    """Scheduled date. Recurring time intervals for standing orders are specified according ISO 8601."""

    container = None
    """If this payment object is a container for multiple payments, then this field is set and contains a ist of payment objects."""

    submission_timestamp = None
    """Timestamp of submission to the bank server."""

    creation_timestamp = None
    """Internal creation timestamp on the figo Connect server."""

    modification_timestamp = None
    """Internal modification timestamp on the figo Connect server."""

    transaction_id = None
    """Transaction ID. This field is only set if the payment has been matched to a transaction."""

    can_be_modified = None
    """List of fields which are modifiable on the bank server"""

    can_be_deleted = None
    """Flag which is set to true if the payment can be deleted from the bank server"""

    def __init__(self, session, **kwargs):
        super(Payment, self).__init__(session, **kwargs)

        if self.submission_timestamp:
            self.submission_timestamp = dateutil.parser.parse(self.submission_timestamp)

        if self.creation_timestamp:
            self.creation_timestamp = dateutil.parser.parse(self.creation_timestamp)

        if self.modification_timestamp:
            self.modification_timestamp = dateutil.parser.parse(self.modification_timestamp)

        if type(self.container) is list:
            self.container = [Payment.from_dict(self, payment_dict) for payment_dict in self.container]

    def __str__(self):
        return "Payment: %s (%s at %s)" % (self.name, self.account_number, self.bank_name)


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
            self.creation_timestamp = dateutil.parser.parse(self.creation_timestamp)

        if self.modification_timestamp:
            self.modification_timestamp = dateutil.parser.parse(self.modification_timestamp)

        if self.booking_date:
            self.booking_date = dateutil.parser.parse(self.booking_date)

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


class Service(object):

    """Object representing a Service"""

    name = None
    """Service name"""

    bank_code = None
    """Bank code of the service"""

    icon = None
    """Icon URL"""

    def __str__(self):
        return "Service: %s (%s)" % (self.name, self.bank_code)


class Task(ModelBase):

    """Object representing a Task"""

    account_id = None
    """Account ID of currently processed account."""

    message = None
    """Status message or error message for currently processed account."""

    is_waiting_for_pin = None
    """If this flag is set, then the figo Connect server waits for a PIN."""

    is_waiting_for_response = None
    """If this flag is set, then the figo Connect server waits for a response to the parameter challenge."""

    is_erroneous = None
    """If this flag is set, then an error occurred and the figo Connect server waits for a continuation."""

    is_ended = None
    """If this flag is set, then the communication with the bank server has been completed."""

    challenge = None
    """Challenge object."""

    def __str__(self):
        return "Task: %s (%s" % (self.message, self.account_id)


class User(ModelBase):

    """Object representing an user"""

    user_id = None
    """Internal figo Connect user ID."""

    name = None
    """"First and last name."""

    email = None
    """"Email address."""

    address = None
    """Postal address for bills, etc."""

    verified_email = None
    """This flag indicates whether the email address has been verified."""

    send_newsletter = None
    """"This flag indicates whether the user has agreed to be contacted by email."""

    language = None
    """"Two-letter code of preferred language."""

    premium = None
    """This flag indicates whether the figo Account plan is free or premium."""

    premium_expires_on = None
    """Timestamp of premium figo Account expiry."""

    premium_subscription = None
    """Provider for premium subscription or Null of no subscription is active."""

    join_date = None
    """Timestamp of figo Account registration."""

    force_reset = None
    """If this flag is set then all local data must be cleared from the device and re-fetched from the figo Connect server."""

    recovery_password = None
    """Auto-generated recovery password. This response parameter will only be set once and only for the figo iOS app and only for legacy figo Accounts. The figo iOS app must display this recovery password to the user."""

    def __init__(self, session, **kwargs):
        super(Payment, self).__init__(session, **kwargs)

        if self.join_date:
            self.join_date = dateutil.parser.parse(self.join_date)

    def __str__(self):
        return "User: %s (%s, %s)" % (self.name, self.user_id, self.email)


class WebhookNotification(ModelBase):

    """Object representing a WebhookNotification"""

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
