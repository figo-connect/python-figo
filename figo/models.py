import sys

import dateutil.parser


class ModelBase(object):
    """Super class for all models. Provides basic serialization."""

    __dump_attributes__ = []

    # Borrowed from Armin Ronacher
    if sys.version_info > (3, 0):
        __str__ = lambda x: x.__unicode__()  # noqa
    else:
        __str__ = lambda x: unicode(x).encode('utf-8')  # noqa

    @classmethod
    def from_dict(cls, session, data_dict):
        """
        Creating an instance of the specific type from the data passed
        in the dictionary `data_dict`.
        """
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
    """Object representing one bank account of the user, independent of the exact account type.

    Attributes:
        account_id: internal figo connect account id
        balance: account balance
        bank_id: internal figo connect bank id
        name: account name
        owner: account owner
        auto_sync: boolean value that indicates whether the account is automatically synchronized
        account_number: account number
        bank_code: bank code
        currency: three character currency code
        iban: iban code
        bic: bic code
        type: account type, one of (Giro account, Savings account, Credit card, Loan account,
                                    PayPal, Cash book, Unknown)
        supported_tan_schemes: List of supported tan schemes
        preferred_tan_scheme: id of preferred tan scheme
        icon: account icon URL
        additional_icons: dictionary that maps resolutions to icon URLs
        status: synchronization status object
    """

    __dump_attributes__ = ["name", "owner", "auto_sync"]

    account_id = None
    balance = None
    bank_id = None
    name = None
    owner = None
    auto_sync = None
    account_number = None
    bank_code = None
    bank_name = None
    currency = None
    iban = None
    bic = None
    type = None
    supported_tan_schemes = None
    preferred_tan_scheme = None
    icon = None
    additional_icons = None
    status = None

    @property
    def bank(self):
        """The corresponding BankContact object for this account."""
        return self.session.get_bank(self.bank_id)

    @property
    def payments(self):
        """An array of `Payment` objects, one for each transaction on the account."""
        return self.session.get_payments(self.account_id)

    def get_payment(self, payment_id):
        """Retrieve a specific payment.

        Args:
            payment_id: id of the payment to be retrieved

        Returns:
            A Payment object representing the payment to be retrieved
        """
        return self.session.get_payments(self.account_id, payment_id)

    @property
    def transactions(self):
        """An array of `Transaction` objects, one for each transaction on the account."""
        return self.session.get_transactions(self.account_id)

    def get_transactions(self, since=None, count=1000, offset=0, include_pending=False):
        """Get an array of `Transaction` objects, one for each transaction of the user.

        Args:
            since: This parameter can either be a transaction ID or a date.
            count: Limit the number of returned transactions
            offset Offset into the result set to determine the first transaction returned
                (useful in combination with count)
            include_pending: boolean, indicates whether pending transactions should be included
                in the response; pending transactions are always included as a
                complete set, regardless of the `since` parameter.

        Returns:
            A list of Transaction objects
        """
        return self.session.get_transactions(self.account_id, since, count, offset, include_pending)

    def get_transaction(self, transaction_id):
        """Retrieve a specific transaction.

        Args:
            transaction_id: id of the transaction to be retrieved

        Returns:
            A Transaction object representing the transaction to be retrieved
        """
        return self.session.get_transaction(self.account_id, transaction_id)

    @property
    def securities(self):
        """An array of `Securities` objects, one for each security on the account."""
        return self.session.get_securities(self.account_id)

    def get_securities(self, since=None, count=1000, offset=0, accounts=None):
        """Get an array of Security objects, one for each security of the user.

        Args:
            account_id: ID of the account for which to list the securities
            since: This parameter can either be a transaction ID or a date.
            count: Limit the number of returned transactions
            offset: Offset into the result set to determine the first security returned
                (useful in combination with count)
            accounts: list of accounts. If retrieving the securities for all accounts, filter
                the securities to be only from these accounts.

        Returns:
            A list of Security objects
        """
        return self.session.get_securities(self.account_id, since, count, offset, accounts)

    def get_security(self, security_id):
        """Retrieve a specific security.

        Args:
             account_id: id of the account on which the security belongs
             security_id: id of the security to be retrieved

        Returns:
            A Security object representing the transaction to be retrieved
        """
        return self.session.get_security(self.account_id, security_id)

    def __unicode__(self):
        return u"Account: %s (%s at %s)" % (self.name, self.account_number, self.bank_name)

    def __init__(self, session, **kwargs):
        super(Account, self).__init__(session, **kwargs)
        if self.status:
            self.status = SynchronizationStatus.from_dict(self.session, self.status)
        if self.balance:
            self.balance = AccountBalance.from_dict(self.session, self.balance)


class BankContact(ModelBase):
    """Object representing a BankContact.

    Attributes:
        bank_id: figo internal bank id
        sepa_creditor_id: SEPA direct debit creditor id
        save_pin: boolean, indicates whether user has chosen to save PIN
    """

    __dump_attributes__ = ["sepa_creditor_id"]

    bank_id = None
    sepa_creditor_id = None
    save_pin = None

    def __unicode__(self):
        return u"BankContact: %s " % self.bank_id


class AccountBalance(ModelBase):
    """Object representing the balance of a certain bank account of the user.

    Attributes:
        balance: acccount balance or None if the balance is not yet known
        balance_date: bank server timestamp of balance or None if the balance is not yet known.
        credit_line: credit line
        monthly_spending_limit: user-defined spending limit
        status: synchronization status object
    """

    __dump_attributes__ = ["credit_line", "monthly_spending_limit"]

    balance = None
    balance_date = None
    credit_line = None
    monthly_spending_limit = None
    status = None

    def __unicode__(self):
        return u"Balance: %d at %s" % (self.balance, str(self.balance_date))

    def __init__(self, session, **kwargs):
        super(AccountBalance, self).__init__(session, **kwargs)
        if self.status:
            self.status = SynchronizationStatus.from_dict(self.session, self.status)

        if self.balance_date:
            self.balance_date = dateutil.parser.parse(self.balance_date)


class Payment(ModelBase):
    """Object representing a Payment.

    When creating a new Payment for submitment to the Figo API all necessary
    fields have to be set on the Payment object.

    Attributes:
        payment_id: internal figo payment id
        account_id: internal figo account id
        type: payment type, one of (Transfer, Direct Debit, SEPA transfer, SEPA direct debit)
        name: name of creditor or debtor
        account_number: account number of creditor or debtor
        bank_code: bank code of creditor or debtor
        bank_code: bank name of creditor or debtor
        amount: order amount
        purpose: purpose text
        bank_icon: icon of creditor or debtor bank
        bank_additional_icons: dictionary that maps resolutions to icon URLs
        amount: order amount
        currency: three character currency code
        purpose: purpose text
        submission_timestamp: submission timestamp
        creation_timestamp: internal creation timestamp
        modification_timestamp: internal creation timestamp
        traditional_id: transaction id, only set if payment has been matched to a transaction
    """

    __dump_attributes__ = ["type", "name", "account_number", "bank_code",
                           "amount", "currency", "purpose"]

    payment_id = None
    account_id = None
    type = None
    name = None
    account_number = None
    bank_code = None
    bank_name = None
    bank_icon = None
    bank_additional_icons = None
    amount = None
    currency = None
    purpose = None
    submission_timestamp = None
    creation_timestamp = None
    modification_timestamp = None
    transaction_id = None

    def __init__(self, session, **kwargs):
        super(Payment, self).__init__(session, **kwargs)

        if self.submission_timestamp:
            self.submission_timestamp = dateutil.parser.parse(self.submission_timestamp)

        if self.creation_timestamp:
            self.creation_timestamp = dateutil.parser.parse(self.creation_timestamp)

        if self.modification_timestamp:
            self.modification_timestamp = dateutil.parser.parse(self.modification_timestamp)

    def __unicode__(self):
        return u"Payment: %s (%s at %s)" % (self.name, self.account_number, self.bank_name)


class StandingOrder(ModelBase):
  """Object representing one standing order on a certain bank account of the user.

  Attributes:
    standing_order_id: internal figo stanging order id
    account_id: internal figo account id
    iban: iban of creditor or debtor
    amount: order amount
    currency: three character currency code
    cents:
    name: name of originator or recipient
    purpose: purpose text
    execution_day: number of days of execution of the standing order
    first_execution_date: starting day of execution
    last_execution_date: finishing day of the execution
    interval:
    created_at: internal creation timestamp
    modified_at: internal creation timestamp
  """

  __dump_attributes__ = []

  standing_order_id = None
  account_id = None
  iban = None
  amount = None
  currency = None
  cents = None
  name = None
  purpose = None
  execution_day = None
  first_execution_date = None
  last_execution_date = None
  interval = None
  created_at = None
  modified_at = None

  def __init__(self, session, **kwargs):
      super(StandingOrder, self).__init__(session, **kwargs)

      if self.created_at:
          self.created_at = dateutil.parser.parse(self.created_at)

      if self.modified_at:
          self.modified_at = dateutil.parser.parse(self.modified_at)

      if self.first_execution_date:
          self.first_execution_date = dateutil.parser.parse(self.first_execution_date)

      if self.last_execution_date:
          self.last_execution_date = dateutil.parser.parse(self.last_execution_date)

  def __unicode__(self):
      return u"Standing Order: %s " % (self.id)

class Transaction(ModelBase):
    """Object representing one bank transaction on a certain bank account of the user.

    Attributes:
        transaction_id: internal figo transaction id
        account_id:  internal figo account id
        name: name of originator or recipient
        account_number: account number of originator or recipient
        bank_code: bank code of originator or recipient
        bank_name: bank name of originator or recipient
        amount: transaction amount
        currency: three-character currency code
        booking_date: booking date
        value_date: value date
        purpose: purpose text
        type: transaction type, one of (Transfer, Standing order, Direct debit, Salary or rent,
            GeldKarte, Charges or interest)
        booking_text: booking text
        booked: boolean, indicates whether transaction is booked or pending
        categories: list of categories assigned to this transaction, ordered from general to
            specific
        creation_timestamp: create date
        modification_timestamp: modification date
        visited: boolean, indicates whether the transaction has already been marked as visited
            by the user
        bic: bic
        iban: iban
        booking_key: booking key
        creditor_id: creditor id
        mandate_reference: mandate reference
        sepa_purpose_code: sepa purpose coe
        sepa_remittance_info: sepa remittance info
        text_key_addition: text key addition
        end_to_end_reference: end to end reference
        customer_reference: customer reference
        prima_nota_number: prima nota number
        additional_info: provides more info about the transaction if available
    """

    __dump_attributes__ = [
        "transaction_id",
        "account_id",
        "name",
        "account_number",
        "bank_code",
        "bank_name",
        "amount",
        "currency",
        "booking_date",
        "value_date",
        "purpose",
        "type",
        "booking_text",
        "booked",
        "categories",
        "creation_timestamp",
        "modification_timestamp",
        "visited",
        "additional_info",
        "bic",
        "iban",
        "booking_key",
        "creditor_id",
        "mandate_reference",
        "sepa_purpose_code",
        "sepa_remittance_info",
        "text_key_addition",
        "end_to_end_reference",
        "customer_reference",
        "prima_nota_number",
    ]

    transaction_id = None
    account_id = None
    name = None
    account_number = None
    bank_code = None
    bank_name = None
    amount = None
    currency = None
    booking_date = None
    value_date = None
    purpose = None
    type = None
    booking_text = None
    booked = None
    categories = None
    creation_timestamp = None
    modification_timestamp = None
    visited = None
    bic = None
    iban = None
    booking_key = None
    creditor_id = None
    mandate_reference = None
    sepa_purpose_code = None
    sepa_remittance_info = None
    text_key_addition = None
    end_to_end_reference = None
    customer_reference = None
    prima_nota_number = None
    additional_info = None

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

    def __unicode__(self):
        return u"Transaction: %d %s to %s at %s" % (self.amount, self.currency,
                                                    self.name, str(self.value_date))


class Category(ModelBase):
    """Object representing a category for a transaction

    Attributes:
        id:
        parent_id:
        name:

    """

    __dump_attributes__ = ["id", "parent_id", "name"]

    id = None
    parent_id = None
    name = None

    def __unicode__(self):
        return self.name


class Notification(ModelBase):
    """Object representing a configured notification, e.g a webhook or email hook.

    Attributes:
        notification_id: internal figo notification ID from the notification registration response
        observe_key: notification key, see http://developer.figo.me/#notification_keys
        notify_uri: notification messages will be sent to this URL
        state: state similiar to sync and login process. It will passed as POST data for webhooks
    """

    __dump_attributes__ = ["observe_key", "notify_uri", "state"]

    notification_id = None
    observe_key = None
    notify_uri = None
    state = None

    def __unicode__(self):
        return u"Notification: %s triggering %s" % (self.observe_key, self.notify_uri)


class SynchronizationStatus(ModelBase):
    """Object representing the synchronization status of the figo servers with banks,
    payment providers or financial service providers.

    Attributes:
        code: internal figo status code
        message: human-readable error message
        sync_timestamp: timestamp of last synchronization
        success_timestamp: timestamp of last successful synchronization
    """

    __dump_attributes__ = []

    code = None
    message = None
    sync_timestamp = None
    success_timestamp = None

    def __unicode__(self):
        return u"Synchronization Status: %s (%s)" % (self.code, self.message)

class Sync(ModelBase):
    """Object representing a syncronisation for account creation.

    Attributes:
        id: internal figo syncronisation id
        status: Current processing state of the item.
        challenge: AuthMethodSelectChallenge (object) or EmbeddedChallenge (object) or RedirectChallenge (object) or DecoupledChallenge (object) (Challenge).
        error: Error detailing why the background operation failed.
        created_at: Time at which the sync was created
        started_at: Time at which the sync started
        ended_at: Time at which the sync ended
    """
    __dump_attributes__ = [
        'id',
        'status',
        'challenge',
        'error',
        'created_at',
        'started_at',
        'ended_at',
    ]

    id = None
    status = None
    challenge = None
    error = None
    created_at = None
    started_at = None
    ended_at = None

    def __init__(self, session, **kwargs):
        super(Sync, self).__init__(session, **kwargs)
        if self.created_at:
            self.created_at = dateutil.parser.parse(self.created_at)

        if self.started_at:
            self.started_at = dateutil.parser.parse(self.started_at)

        if self.ended_at:
            self.ended_at = dateutil.parser.parse(self.ended_at)

        if self.challenge:
            self.challenge = Challenge.from_dict(self.session, self.challenge)

    def __unicode__(self):
        return u"Sync: %s" % (self.id)

    def dump(self):
        dumped_value = super(Sync, self).dump()
        if self.challenge:
            dumped_value.update({
                'challenge': self.challenge.dump()
            })

        return dumped_value


class User(ModelBase):
    """Object representing an user.

    Attributes:
        user_id: internal figo user id
        name: full name
        email: email address
        address: postal address
        verified_email: boolean, indicates whether the email address has been verified
        send_newsletter: boolean, incicates whether the user has signed up for the newsletter
        language: two letter code for preferred language
        premium: --
        premium_expires_on: --
        join_date: --

    """

    __dump_attributes__ = ["name", "address", "send_newsletter", "language"]

    user_id = None
    name = None
    email = None
    address = None
    verified_email = None
    send_newsletter = None
    language = None
    premium = None
    premium_expires_on = None
    premium_subscription = None
    join_date = None

    def __init__(self, session, **kwargs):
        super(User, self).__init__(session, **kwargs)

        if self.join_date:
            self.join_date = dateutil.parser.parse(self.join_date)

    def __unicode__(self):
        return u"User: %s (%s, %s)" % (self.name, self.user_id, self.email)


class WebhookNotification(ModelBase):
    """Object representing a WebhookNotification.

    Attributes:
        notification_id: internal figo notification ID from the notification registration response
        observe_key: notification key
        state: the state parameter from the notification registration request
        data: object or list with the data (AccountBalance or Transaction)
    """

    __dump_attributes__ = []

    notification_id = None
    observe_key = None
    state = None
    data = None

    def __unicode__(self):
        return u"WebhookNotification: %s" % (self.notification_id)


class Service(ModelBase):
    """Object representing a payment service.

    Attributes:
        name: human readable name of the service
        bank_code: surrogate bank code used for this service
        state: URL to a logo of the bank
        additional_icons: dictionary that maps resolutions to icon URLs
        language: the language the service description is in
        available_languages: list of other available languages
    """

    __dump_attributes__ = ["name", "bank_code", "icon", "additional_icons", "language"]

    name = None
    bank_code = None
    state = None
    additional_icons = None
    language = None
    available_languages = []

    def __init__(self, session, **kwargs):
        super(Service, self).__init__(session, **kwargs)
        if self.language:
            self.available_languages = [l for l in self.language['available']]
            self.language = self.language['current']

    def __unicode__(self, *args, **kwargs):
        return u"Service: %s" % (self.bank_code)


class LoginSettings(ModelBase):
    """Object representing login settings for a banking service.

    Attributes:
        bank_name: human readable bank of the bank
        supported: boolean, if set bank is supported
        icon: URL to the logo of the bank
        additional_icons: dictionary that maps resolutions to icon URLs
        credentials: list of credentials needed to connect to the bank
        auth_type: kind of authentication used by the bank
        advice: any additional advice useful to locate the required credentials
    """

    __dump_attributes__ = ['id', 'name', 'icon', 'supported', 'country',
                           'language', 'bic', 'access_methods', 'bank_code', ]

    id = None
    name = None
    icon = None
    supported = None
    country = None
    language = None
    bic = None
    access_methods = None
    bank_code = None

    def __unicode__(self, *args, **kwargs):
        return u"LoginSettings: %s" % (self.name)


class Credential(ModelBase):
    """Object representing a login credential field for a banking service.

    Attributes:
        label: label for text input field
        masked: boolean, if set the text input field is used for password entry and should be
            masked
        optional: boolean, if set the field is optional and may be an empty string
    """

    __dump_attributes__ = ["label", "masked", "optional"]

    label = None
    masked = None
    optional = None

    def __unicode__(self, *args, **kwargs):
        return u"Credential: %s" % (self.label)


class TaskToken(ModelBase):
    """Object representing a task token.

    Attributes:
        task_token:
    """

    __dump_attributes__ = ["task_token"]

    task_token = None

    def __unicode__(self, *args, **kwargs):
        return u"TaskToken: %s" % (self.task_token)


class TaskState(ModelBase):
    """Object representing a tasks state.

    Attributes:
        account_id: account id of currently processed account
        message: status message or error message for currently processed account
        is_waiting_for_pin: boolean, if set the figo server is waiting for PIN
        is_waiting_for_response: boolean, if set the figo server is waiting for a response to
            the parameter challenge
        is_erroneous: boolean, if set an error occurred
        is_ended: boolean, if set the communication with the bank has been completed
        challenge: challenge object
        error: dictionary, populated in the case of error

    """

    __dump_attributes__ = ["account_id", "message", "is_waiting_for_pin",
                           "is_waiting_for_response", "is_erroneous",
                           "is_ended", "challenge", "error"]

    account_id = None
    message = None
    is_waiting_for_pin = None
    is_waiting_for_response = None
    is_erroneous = None
    is_ended = None
    challenge = None
    error = None

    def __unicode__(self, *args, **kwargs):
        return (u"TaskState: '{self.message}' (is_erroneous: {self.is_erroneous}, "
                "is_ended: {self.is_ended})".format(self=self))


class Challenge(ModelBase):
    """Object representing a challenge.

    Attributes:
        title: challenge title
        label: response label
        format: challenge data format, one of (Text, HTML, HHD, Matrix)
        data: challenge data

    """
    __dump_attributes__ = ["id", "title", "label", "format", "data", "type"]

    id = None
    title = None
    label = None
    format = None
    data = None
    type = None

    def __unicode__(self, *args, **kwargs):
        return u"Challenge: %s" % (self.title)


class PaymentProposal(ModelBase):
    """Object representing a payment proposal.

    Attributes:
        account_number: Account number or IBAN
        bank_code: bank code or BIC
        name: Name of the payment proposal
    """

    __dump_attributes__ = ["account_number", "bank_code", "name"]

    account_number = None
    bank_code = None
    name = None

    def __unicode__(self, *args, **kwargs):
        return u"Payment Proposal: %s" % (self.name)


class Process(ModelBase):
    """Object representing a Business Process.

    Attributes:
        email: The email of the existing user to use as context or the new user to create
            beforehand. In the latter case it must obey the figo username & password policy.
        password: The password of the user existing or new user. In the latter case it must obey
            the figo username & password policy.
        redirect_uri: The authorization code will be sent to this callback URL. It must match one
            of the URLs registered during application registration.
        state: Any kind of string that will be forwarded in the callback response message. It
            serves two purposes: The value is used to maintain state between this request and the
            callback, e.g. it might contain a session ID from your application. The value should
            also contain a random component, which your application checks to mitigate cross-site
            request forgery.
        steps: A list of step definitions. Each step definition is a dictionary with type and
            options keys, where type is the name of step type and options is another dictionary
            containing all the settings for the respective step.
    """

    __dump_attributes__ = ["email", "password", "redirect_uri", "state", "steps"]

    email = None
    password = None
    redirect_uri = None
    state = None
    steps = None


class ProcessStep(ModelBase):
    """Object representing a process step.

    Attributes:
        type: name of step type
        options: settings for respective step
    """

    __dump_attributes__ = ["type", "options"]

    type = None
    options = None

    def __unicode__(self, *args, **kwargs):
        return u"ProcessStep Type: %s" % (self.type)


class ProcessOptions(ModelBase):
    """Object representing a process option.

    Attributes:
        account_number:
        amount:
        bank_code:
        currency:
        name:
        purpose:
        type:
    """

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
    """Object representing a process token.

    Attributes:
        process_token:
    """

    __dump_attributes__ = ["process_token"]

    process_token = None

    def __unicode__(self, *args, **kwargs):
        return u"Process Token: %s" % (self.process_token)


class Security(ModelBase):
    """Object representing one bank security on a certain bank account of the user.

    Attributes:
        security_id: internal figo connect security id
        account_id: internal figo connect account id
        name: name of originator or recipient
        isin: international securities identification number
        wkn: wertpapierkennnummer
        currency: three character currency code
        amount: monetary value in account currency
        quantity: number of securities or value
        amount_original_currency: monetary value in trading currency
        exchange_rate: exchange rate between trading and account currency
        price: current price
        price_currency: currency of current price
        purchase_price: purchase price
        purchase_price_currency: currency of purchase price
        visited: boolean that indicates whether the security has been marked as visited by the user
        trade_timestamp: trade timestamp
        creation_timestamp: internal creation timestamp
        modification_timestamp: internal modification timestamp

    """

    __dump_attributes__ = []

    security_id = None
    account_id = None
    name = None
    isin = None
    wkn = None
    currency = None
    amount = None
    quantity = None
    amount_original_currency = None
    exchange_rate = None
    price = None
    price_currency = None
    purchase_price = None
    purchase_price_currency = None
    visited = None
    trade_timestamp = None
    creation_timestamp = None
    modification_timestamp = None

    def __init__(self, session, **kwargs):
        super(Security, self).__init__(session, **kwargs)

        if self.trade_timestamp:
            self.trade_timestamp = dateutil.parser.parse(self.trade_timestamp)

        if self.creation_timestamp:
            self.creation_timestamp = dateutil.parser.parse(self.creation_timestamp)

        if self.modification_timestamp:
            self.modification_timestamp = dateutil.parser.parse(self.modification_timestamp)

    def __unicode__(self):
        return u"Security: %d %s to %s at %s" % (self.amount, self.currency, self.name,
                                                 self.trade_timestamp)
