
import dateutil.parser


class ModelBase(object):

    """Super class for all models. Provides basic serialization."""

    __dump_attributes__ = []

    @classmethod
    def from_dict(cls, session, data_dict):
        """
        Creating an instance of the specific type from the data passed
        in the dictionary `data_dict`."""
        return cls(session, **data_dict)

    def __init__(self, session, **kwargs):
        self.session = session
        for key, value in kwargs.items():
            setattr(self, key, value)

    def dump(self):
        """Serialize the ModelBase object to a dictionary."""
        result = {}
        for attribute in self.__dump_attributes__:
            value = getattr(self, attribute)
            if value is not None:
                result[attribute] = value
        return result


class Account(ModelBase):

    """Object representing one bank account of the user, independent of the exact account type."""

    __dump_attributes__ = ["name", "owner", "auto_sync"]

    account_id = None
    """Internal figo Connect account ID"""

    # Attribute added by Fincite (http://fincite.de) on 06/03/2015
    balance = None
    """Account balance"""

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
    """
    Account type:
        Giro account
        Savings account
        Credit card
        Loan account
        PayPal
        Cash book
        Unknown
    """

    supported_tan_schemes = None
    """List of supported tan schemes"""

    preferred_tan_scheme = None
    """ID of the preferred tan scheme"""

    icon = None
    """Account icon URL"""

    additional_icons = None
    """Account icon in other resolutions"""

    status = None
    """Synchronization status object"""

    @property
    def bank(self):
        """The corresponding BankContact object for this account."""
        return self.session.get_bank(self.bank_id)

    @property
    def payments(self):
        """An array of `Payment` objects, one for each transaction on the account."""
        return self.session.get_payments(self.account_id)

    def get_payment(self, payment_id):
        """
        Retrieve a specific payment.

        :Parameters:
         - `payment_id` - ID of the payment to be retrieved

        :Returns:
            a `Payment` object representing the payment to be retrieved
        """
        return self.session.get_payments(self.account_id, payment_id)

    @property
    def transactions(self):
        """An array of `Transaction` objects, one for each transaction on the account."""
        return self.session.get_transactions(self.account_id)

    def get_transactions(self, since=None, count=1000, offset=0, include_pending=False):
        """
        Get an array of `Transaction` objects, one for each transaction of the user.

        Args:
         since (str): This parameter can either be a transaction ID or a date.
         count (int): Limit the number of returned transactions
         offset (int): Offset into the result set to determine the first transaction returned
                       (useful in combination with count)
         nclude_pending (bool): This flag indicates whether pending transactions should be included
                                in the response; pending transactions are always included as a
                                complete set, regardless of the `since` parameter.

        Returns:
            [Transaction]: List of Transaction objects
        """
        return self.session.get_transactions(self.account_id, since, count, offset, include_pending)

    def get_transaction(self, transaction_id):
        """
        Retrieve a specific transaction.

        :Parameters:
         - `transaction_id` - ID of the transaction to be retrieved

        :Returns:
            a `Transaction` object representing the transaction to be retrieved
        """
        return self.session.get_transaction(self.account_id, transaction_id)

    # Method added by Fincite (http://fincite.de) on 06/03/2015
    @property
    def securities(self):
        """An array of `Securities` objects, one for each security on the account."""
        return self.session.get_securities(self.account_id)

    # Method added by Fincite (http://fincite.de) on 06/03/2015
    def get_securities(self, since=None, count=1000, offset=0, accounts=None):
        """
        Get an array of `Security` objects, one for each security of the user.

        Args:
         account_id (str): ID of the account for which to list the securities
         since (str): This parameter can either be a transaction ID or a date.
         count (int): Limit the number of returned transactions
         offset (int): Offset into the result set to determine the first security returned
                       (useful in combination with count)
         accounts ([str]): If retrieving the securities for all accounts, filter the securities
                           to be only from these accounts.

        Returns:
            [Security]: List of Security objects
        """
        return self.session.get_securities(self.account_id, since, count, offset, accounts)

    # Method added by Fincite (http://fincite.de) on 06/03/2015
    def get_security(self, security_id):
        """Retrieve a specific security.

        :Parameters:
         - `account_id` - ID of the account on which the security belongs
         - `security_id` - ID of the security to be retrieved

        :Returns:
            a `Security` object representing the transaction to be retrieved
        """
        return self.session.get_security(self.account_id, security_id)

    def __str__(self):
        """Short String representation of an Account object."""
        return "Account: %s (%s at %s)" % (self.name, self.account_number, self.bank_name)

    def __init__(self, session, **kwargs):
        super(Account, self).__init__(session, **kwargs)
        if self.status:
            self.status = SynchronizationStatus.from_dict(self.session, self.status)
        if self.balance:
            self.balance = AccountBalance.from_dict(self.session, self.balance)


class BankContact(ModelBase):

    """Object representing a BankContact."""

    __dump_attributes__ = ["sepa_creditor_id"]

    bank_id = None
    """Internal figo Connect bank ID"""

    sepa_creditor_id = None
    """SEPA direct debit creditor ID."""

    save_pin = None
    """
    This flag indicates whether the user has chosen to save the PIN on the figo Connect server.
    """

    def __str__(self):
        """Short String representation of the bank contact."""
        return "BankContact: %s " % self.bank_id


class AccountBalance(ModelBase):

    """Object representing the balance of a certain bank account of the user."""

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
        """Short String representation of the account balance."""
        return "Balance: %d at %s" % (self.balance, str(self.balance_date))

    def __init__(self, session, **kwargs):
        super(AccountBalance, self).__init__(session, **kwargs)
        if self.status:
            self.status = SynchronizationStatus.from_dict(self.session, self.status)

        if self.balance_date:
            self.balance_date = dateutil.parser.parse(self.balance_date)


class Payment(ModelBase):

    """
    Object representing a Payment.

    When creating a new Payment for submitment to the Figo API all necessary
    fields have to be set on the Payment object.

    Required fields:
        - account_id        -   Internal figo connect ID of the account
        - type              -   Payment type (Valid values: Transfer, Direct Debit, SEPA transfer, SEPA direct debit)
        - name              -   Name of creditor or debtor
        - account_number    -   Account number of creditor or debtor
        - bank_code         -   Bank code of creditor or debtor
        - amount            -   Order amount
        - purpose           -   Purpose text

    Optional fields:
        - currency                  -   Three-character currency code (Default: EUR / Valid values: EUR)
        - text_key                  -   DTA text key
        - text_key_extension        -   DTA text key extension
        - notification_recipient    -   Recipient of the payment notification, should be an email address
        - cents                     -   If true, the amount is submitted and displayed as cents
    """

    __dump_attributes__ = ["type", "name", "account_number", "bank_code",
                           "amount", "currency", "purpose"]

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
        """Short String representation of a Payment."""
        return "Payment: %s (%s at %s)" % (self.name, self.account_number, self.bank_name)


class Transaction(ModelBase):

    """Object representing one bank transaction on a certain bank account of the user."""

    __dump_attributes__ = ["transaction_id", "account_id", "name",
                           "account_number", "bank_code", "bank_name", "amount",
                           "currency", "booking_date", "value_date", "purpose",
                           "type", "booking_text", "booked", "categories", "creation_timestamp",
                           "modification_timestamp", "visited", "additional_info"]

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
    """
    Transaction type:
        Transfer
        Standing order
        Direct debit
        Salary or rent
        GeldKarte
        Charges or interest
        """

    booking_text = None
    """Booking text"""

    booked = None
    """This flag indicates whether the transaction is booked or pending"""

    categories = None
    """List of categories assigned to this transaction, ordered from general to specific"""

    creation_timestamp = None
    """creation date"""

    modification_timestamp = None
    """modification date"""

    visited = None
    """This flag indicates whether the transaction has already been marked as visited by the user"""

    additional_info = None
    """Provides more info about the transaction if available, depends on the account type"""

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

        if self.categories:
            self.categories = [Category.from_dict(session, c) for c in self.categories]

    def __str__(self):
        """Short String representation of a Transaction."""
        return "Transaction: %d %s to %s at %s" % (self.amount, self.currency,
                                                   self.name, str(self.value_date))


class Category(ModelBase):

    """Object representing a category for a transaction"""

    __dump_attributes__ = ["id", "parent_id", "name"]

    id = None

    parent_id = None

    name = None

    def __str__(self):
        return self.name


class Notification(ModelBase):

    """Object representing a configured notification, e.g a webhook or email hook."""

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
        """Short String representation of a Notification."""
        return "Notification: %s triggering %s" % (self.observe_key, self.notify_uri)


class SynchronizationStatus(ModelBase):

    """
    Object representing the synchronization status of the figo servers with e banks,
    payment providers or financial service providers.
    """

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
        """Short String representation of a synchronizationStatus."""
        return "Synchronization Status: %s (%s)" % (self.code, self.message)


class User(ModelBase):

    """Object representing an user."""

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
        """Short String representation of a User."""
        return "User: %s (%s, %s)" % (self.name, self.user_id, self.email)


class WebhookNotification(ModelBase):

    """Object representing a WebhookNotification."""

    __dump_attributes__ = []

    notification_id = None
    """Internal figo Connect notification ID from the notification registration
    response."""

    observe_key = None
    """The Notification key"""

    state = None
    """The state parameter from the notification registration request."""

    data = None
    """Object or List with the data (`AccountBalance` or `Transaction`)"""

    def __str__(self):
        """Short String representation of a WebhookNotification."""
        return "WebhookNotification: %s" % (self.notification_id)


class Service(ModelBase):

    """Object representing a payment service."""

    __dump_attributes__ = ["name", "bank_code", "icon", "additional_icons"]

    name = None
    """Human readable name of the service"""

    bank_code = None
    """surrogate bank code used for this service"""

    state = None
    """URL to an logo of the bank, e.g. as a badge icon"""

    additional_icons = None
    """Dictionary mapping from resolution to URL for additional resolutions of
    the banks icon."""

    def __str__(self, *args, **kwargs):
        """Short String representation of a Service."""
        return "Service: %s" % (self.bank_code)


class LoginSettings(ModelBase):

    """Object representing login settings for a banking service."""

    __dump_attributes__ = ["bank_name", "supported", "icon", "additional_icons",
                           "credentials", "auth_type", "advice"]

    bank_name = None
    """Human readable name of the bank"""

    supported = None
    """Flag showing whether figo supports the bank"""

    icon = None
    """URL to an logo of the bank, e.g. as a badge icon"""

    additional_icons = None
    """Dictionary mapping from resolution to URL for additional resolutions of
    the banks icon."""

    credentials = None
    """List of credentials needed to connect to the bank."""

    auth_type = None
    """Kind of authentication used by the bank, commonly PIN"""

    advice = None
    """Any additional advice useful to locate the required credentials"""

    def __str__(self, *args, **kwargs):
        """Short String representation of a LoginSettings object."""
        return "LoginSettings: %s" % (self.bank_name)


class Credential(ModelBase):

    """Object representing a login credential field for a banking service."""

    __dump_attributes__ = ["label", "masked", "optional"]

    label = None
    """Label for text input field"""

    masked = None
    """This indicates whether the this text input field is used for password
    entry and therefore should be masked"""

    optional = None
    """This flag indicates whether this text input field is allowed to contain
    the empty string"""

    def __str__(self, *args, **kwargs):
        """Short String representation of a Credential."""
        return "Credential: %s" % (self.label)


class TaskToken(ModelBase):

    """Object representing a task token."""

    __dump_attributes__ = ["task_token"]

    task_token = None

    def __str__(self, *args, **kwargs):
        """Short String representation of a TaskToken."""
        return "TaskToken: %s" % (self.task_token)


class TaskState(ModelBase):

    """Object representing a tasks state."""

    __dump_attributes__ = ["account_id", "message", "is_waiting_for_pin",
                           "is_waiting_for_response", "is_erroneous",
                           "is_ended", "challenge", "error"]

    account_id = None
    """Account ID of currently processed account"""

    message = None
    """Status message or error message for currently processed account"""

    is_waiting_for_pin = None
    """If this flag is set, then the figo Connect server waits for a PIN"""

    is_waiting_for_response = None
    """If this flag is set, then the figo Connect server waits for a response to
    the parameter challenge"""

    is_erroneous = None
    """If this flag is set, then an error occurred and the figo Connect server
    waits for a continuation"""

    is_ended = None
    """If this flag is set, then the communication with the bank server has been completed"""

    challenge = None
    """Challenge object"""

    error = None
    """Dict populated in case of an error"""

    def __str__(self, *args, **kwargs):
        """Short String representation of a TaskState."""
        string = (u"TaskState: '{self.message}' "
                  u"(is_erroneous: {self.is_erroneous}, "
                  u"is_ended: {self.is_ended})")

        # BBB(Valentin): All strings come in UTF-8 from JSON. But:
        #   - python2.6: encode knows no kwargs
        #   - python2.7: `u"{0}".format(x)` returns `unicode`, `__str__()` excpects `str` (ASCII)
        #   - python3.x: encode returns `bytes`,`__str__` expects `str` (UTF-8)
        #   This is really ugly, but works in all pythons.
        return str(string.format(self=self).encode('ascii', 'replace'))


class Challenge(ModelBase):

    """Object representing a challenge."""

    __dump_attributes__ = ["title", "label", "format"]

    title = None
    """Challenge title"""

    label = None
    """Response label"""

    format = None
    """Challenge data format. Possible values are Text, HTML, HHD or Matrix."""

    data = None
    """Challenge data"""

    def __str__(self, *args, **kwargs):
        """Short String representation of a Challenge."""
        return "Challenge: %s" % (self.title)


class PaymentProposal(ModelBase):

    """Object representing a payment proposal."""

    __dump_attributes__ = ["account_number", "bank_code", "name"]

    account_number = None
    """Account number or IBAN"""

    bank_code = None
    """bank code or BIC"""

    name = None
    """Name of the payment proposal"""

    def __str__(self, *args, **kwargs):
        """Short String representation of a PaymentProposal."""
        return "Payment Proposal: %s" % (self.name)


class Process(ModelBase):

    """Object representing a Business Process."""

    __dump_attributes__ = ["email", "password", "redirect_uri", "state", "steps"]

    email = None
    """The email of the existing user to use as context or the new user to
    create beforehand. In the latter case it must obey the figo username &
    password policy"""

    password = None
    """The password of the user existing or new user. In the latter case it must
    obey the figo username & password policy"""

    redirect_uri = None
    """The authorization code will be sent to this callback URL. It must match
    one of the URLs registered during application registration."""

    state = None
    """Any kind of string that will be forwarded in the callback response
    message. It serves two purposes: The value is used to maintain state between
    this request and the callback, e.g. it might contain a session ID from your
    application. The value should also contain a random component, which your
    application checks to mitigate cross-site request forgery."""

    steps = None
    """A list of step definitions. Each step definition is a dictionary with
    type and options keys, where type is the name of step type and options is
    another dictionary containing all the settings for the respective step"""


class ProcessStep(ModelBase):

    """Object representing a process step."""

    __dump_attributes__ = ["type", "options"]

    type = None
    """name of step type"""

    options = None
    """settings for the respective step"""

    def __str__(self, *args, **kwargs):
        """Short String representation of a ProcessStep."""
        return "ProcessStep Type: %s" % (self.type)


class ProcessOptions(ModelBase):

    """Object representing a process option."""

    __dump_attributes__ = ["account_number", "amount", "bank_code", "currency",
                           "name", "purpose", "type"]

    account_number = None

    amount = None

    bank_code = None

    currency = None

    name = None

    purpose = None

    type = None


class ProcessToken(ModelBase):

    """Object representing a process token."""

    __dump_attributes__ = ["process_token"]

    process_token = None

    def __str__(self, *args, **kwargs):
        """Short String representation of a ProcessToken."""
        return "Process Token: %s" % (self.process_token)


# Class added by Fincite (http://fincite.de) on 06/03/2015
class Security(ModelBase):

    """Object representing one bank security on a certain bank account of the user."""

    __dump_attributes__ = []

    security_id = None
    """Internal figo Connect security ID"""

    account_id = None
    """Internal figo Connect account ID"""

    name = None
    """Name of originator or recipient"""

    isin = None
    """International Securities Identification Number"""

    wkn = None
    """Wertpapierkennnummer (if available)"""

    currency = None
    """Three-character currency code when measured in currency (and not pieces)"""

    amount = None
    """Monetary value in account currency"""

    quantity = None
    """Number of pieces or value"""

    amount_original_currency = None
    """Monetary value in trading currency"""

    exchange_rate = None
    """Exchange rate between trading and account currency"""

    price = None
    """Current price"""

    price_currency = None
    """Currency of current price"""

    purchase_price = None
    """Purchase price"""

    purchase_price_currency = None
    """Currency of purchase price"""

    visited = None
    """This flag indicates whether the security has already been marked as visited by the user"""

    trade_timestamp = None
    """Trading timestamp"""

    creation_timestamp = None
    """Internal creation timestamp on the figo Connect server"""

    modification_timestamp = None
    """Internal modification timestamp on the figo Connect server"""

    def __init__(self, session, **kwargs):
        super(Security, self).__init__(session, **kwargs)

        if self.trade_timestamp:
            self.trade_timestamp = dateutil.parser.parse(self.trade_timestamp)

        if self.creation_timestamp:
            self.creation_timestamp = dateutil.parser.parse(self.creation_timestamp)

        if self.modification_timestamp:
            self.modification_timestamp = dateutil.parser.parse(self.modification_timestamp)

    def __str__(self):
        """Short String representation of a Security."""
        return "Security: %d %s to %s at %s" % (self.amount, self.currency, self.name,
                                                str(self.trade_timestamp))
