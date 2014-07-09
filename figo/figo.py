#
#  Created by Stefan Richter on 2013-01-12.
#  Copyright (c) 2013 figo GmbH. All rights reserved.
#

import base64
from datetime import datetime, timedelta
import hashlib
import json
import logging
import re
import socket
import ssl
import sys
import urllib

if sys.version_info[0] > 2:
    import http.client as httplib
    from itertools import zip_longest as izip_longest
else:
    import httplib
    from itertools import izip_longest


from .models import *


logger = logging.getLogger(__name__)


class VerifiedHTTPSConnection(httplib.HTTPSConnection):

    """HTTPSConnection supporting certificate authentication based on fingerprint"""

    VALID_FINGERPRINTS = ("3A:62:54:4D:86:B4:34:38:EA:34:64:4E:95:10:A9:FF:37:27:69:C0",
                          "CF:C1:BC:7F:6A:16:09:2B:10:83:8A:B0:22:4F:3A:65:D2:70:D7:3E")

    def connect(self):
        # overrides the version in httplib so that we do certificate verification
        if sys.hexversion >= 0x02070000:
            sock = socket.create_connection((self.host, self.port), self.timeout, self.source_address)
        else:
            sock = socket.create_connection((self.host, self.port), self.timeout)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()

        # wrap the socket
        self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file)

        # verify the certificate fingerprint
        certificate = self.sock.getpeercert(True)
        if certificate is None:
            raise ssl.SSLError("Certificate validation failed")
        else:
            fingerprint = hashlib.sha1(certificate).hexdigest()
            fingerprint = ":".join(["".join(x) for x in izip_longest(*[iter(fingerprint.upper())] * 2)])
            if fingerprint not in VerifiedHTTPSConnection.VALID_FINGERPRINTS:
                raise ssl.SSLError("Certificate validation failed")


class FigoObject(object):

    API_ENDPOINT = "api.figo.me"
    API_SECURE = True

    def _query_api(self, path, data=None, method="GET"):
        """Helper method for making a REST-compliant API call

        :Parameters:
         - `path` - path on the server to call
         - `data` - Dictionary of data to send to the server in message body
         - `method` - HTTP verb to use for the request

        :Returns:
            the JSON-parsed result body
        """

        connection = VerifiedHTTPSConnection(
            self.API_ENDPOINT) if self.API_SECURE else httplib.HTTPConnection(self.API_ENDPOINT)
        connection.request(method, path, None if data is None else json.dumps(data),
                           {'Authorization': "Bearer %s" % self.access_token, 'Accept': 'application/json', 'Content-Type': 'application/json'})
        response = connection.getresponse()

        if response.status >= 200 and response.status < 300:
            response_data = response.read().decode("utf-8")
            if response_data == "":
                return {}
            return json.loads(response_data)
        elif response.status == 400:
            response_data = response.read().decode("utf-8")
            return json.loads(response_data)
        elif response.status == 401:
            return {'error': "unauthorized", 'error_description': "Missing, invalid or expired access token."}
        elif response.status == 403:
            return {'error': "forbidden", 'error_description': "Insufficient permission."}
        elif response.status == 404:
            return None
        elif response.status == 405:
            return {'error': "method_not_allowed", 'error_description': "Unexpected request method."}
        elif response.status == 503:
            return {'error': "service_unavailable", 'error_description': "Exceeded rate limit."}
        else:
            logger.warn("Querying the API failed when accessing '%s': %d", path, response.status)
            return {'error': "internal_server_error", 'error_description': "We are very sorry, but something went wrong"}

    def _query_api_with_exception(self, path, data=None, method="GET"):
        """Helper method analog to _query_api but raises an exception instead of simply returning"""
        response = self._query_api(path, data, method)
        if 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return response


class FigoException(Exception):

    """Base class for all exceptions transported via the figo connect API.

    They consist of a code-like `error` and a human readable `error_description`.
    """

    def __init__(self, error, error_description):
        super(FigoException, self).__init__()

        self.error = error
        self.error_description = error_description

    def __str__(self):
        return "FigoException: %s(%s)" % (repr(self.error_description), repr(self.error))

    @classmethod
    def from_dict(cls, dictionary):
        """Helper function creating an exception instance from the dictionary returned by the server"""
        return cls(dictionary['error'], dictionary['error_description'])


class FigoConnection(FigoObject):

    """Representing a not user-bound connection to the figo connect API.

    Its main purpose is to let user login via the OAuth2 API.
    """

    def __init__(self, client_id, client_secret, redirect_uri):
        """Creates a FigoConnection instance.

        :Parameters:
         - `client_id` - the OAuth Client ID as provided by your figo developer contact
         - `client_secret` - the OAuth Client Secret as provided by your figo developer contact
         - `redirect_uri` - the URI the users gets redirected to after the login is finished or if he presses cancels
        """

        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri

    def _query_api(self, path, data=None):
        """Helper method for making a OAuth2-compliant API call

        :Parameters:
         - `path` - path on the server to call
         - `data` - Dictionary of data to send to the server in message body

        :Returns:
            the JSON-parsed result body
        """

        connection = VerifiedHTTPSConnection(self.API_ENDPOINT) if self.API_SECURE else httplib.HTTPConnection(self.API_ENDPOINT)
        connection.request("POST", path, urllib.urlencode(data),
                           {'Authorization': "Basic %s" % base64.b64encode(self.client_id + ":" + self.client_secret),
                            'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'})
        response = connection.getresponse()

        if response.status >= 200 and response.status < 300:
            response_data = response.read().decode("utf-8")
            if response_data == "":
                return {}
            return json.loads(response_data)
        elif response.status == 400:
            response_data = response.read().decode("utf-8")
            return json.loads(response_data)
        elif response.status == 401:
            return {'error': "unauthorized", 'error_description': "Missing, invalid or expired access token."}
        elif response.status == 403:
            return {'error': "forbidden", 'error_description': "Insufficient permission."}
        elif response.status == 404:
            return None
        elif response.status == 405:
            return {'error': "method_not_allowed", 'error_description': "Unexpected request method."}
        elif response.status == 503:
            return {'error': "service_unavailable", 'error_description': "Exceeded rate limit."}
        else:
            logger.warn("Querying the API failed when accessing '%s': %d", path, response.status)
            return {'error': "internal_server_error", 'error_description': "We are very sorry, but something went wrong"}

    def login_url(self, scope, state):
        """The URL a user should open in his/her web browser to start the login process.

        When the process is completed, the user is redirected to the URL provided to the constructor and passes on an authentication code. This code can be converted into an access token for data access.

        :Parameters:
         - `scope` - Scope of data access to ask the user for, e.g. `accounts=ro`
         - `state` - String passed on through the complete login process and to the redirect target at the end. It should be used to validated the authenticity of the call to the redirect URL

        :Returns:
            the URL of the first page of the login process
        """
        return ("https://" if self.API_SECURE else "http://") + self.API_ENDPOINT + "/auth/code?" + urllib.urlencode({'response_type': 'code', 'client_id': self.client_id, 'redirect_uri': self.redirect_uri, 'scope': scope, 'state': state})

    def convert_authentication_code(self, authentication_code):
        """Convert the authentication code received as result of the login process into an access token usable for data access.

        :parameters:
         - `authentication_code` - the code received as part of the call to the redirect URL at the end of the logon process

        :returns:
            Dictionary with the following keys:
             - `access_token` - the access token for data access. You can pass it into `FigoConnection.open_session` to get a FigoSession and access the users data
             - `refresh_token` - if the scope contained the `offline` flag, also a refresh token is generated. It can be used to generate new access tokens, when the first one has expired.
             - `expires` - absolute time the access token expires
        """

        if authentication_code[0] != "O":
            raise Exception("Invalid authentication code")

        response = self._query_api("/auth/token", data={
                                   'code': authentication_code, 'redirect_uri': self.redirect_uri, 'grant_type': 'authorization_code'})
        if 'error' in response:
            raise FigoException.from_dict(response)

        return {'access_token': response['access_token'],
                'refresh_token': response['refresh_token'] if 'refresh_token' in response else None,
                'expires': datetime.now() + timedelta(seconds=response['expires_in'])}

    def convert_refresh_token(self, refresh_token):
        """Convert a refresh token (granted for offline access and returned by `convert_authentication_code`) into an access token usabel for data acccess.

        :Parameters:
         - `refresh_token` - refresh token returned by `convert_authentication_code`

        :Returns:
            Dictionary with the following keys:
             - `access_token` - the access token for data access. You can pass it into `FigoConnection.open_session` to get a FigoSession and access the users data
             - `expires` - absolute time the access token expires
        """

        if refresh_token[0] != "R":
            raise Exception("Invalid refresh token")

        response = self._query_api("/auth/token", data={
                                   'refresh_token': refresh_token, 'redirect_uri': self.redirect_uri, 'grant_type': 'refresh_token'})
        if 'error' in response:
            raise FigoException.from_dict(response)

        return {'access_token': response['access_token'],
                'expires': datetime.now() + timedelta(seconds=response['expires_in'])}

    def revoke_token(self, token):
        """Revoke a granted access or refresh token and thereby invalidate it.

        Note: this action has immediate effect, i.e. you will not be able use that token anymore after this call.

        :Parameters:
         - `token` - access or refresh token to be revoked
        """

        response = self._query_api("/auth/revoke?" + urllib.urlencode({'token': token}))
        if 'error' in response:
            raise FigoException.from_dict(response)

    def add_user(self, name, email, password, language='de', send_newsletter=True):
        """Create a new figo Account.

        :Parameters:
        - `name` - First and last name
        - `email` - Email address; It must obey the figo username & password policy
        - `password` - New figo Account password; It must obey the figo username & password policy
        - `language` - Two-letter code of preferred language
        - `send_newsletter` - This flag indicates whether the user has agreed to be contacted by email

        :Returns:
            Auto-generated recovery password.
        """

        response = self._query_api("/auth/user", {'name': name, 'email': email, 'password': password, 'language': language, 'send_newsletter': send_newsletter, 'affiliate_client_id': self.client_id}, method="POST")
        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return response['recovery_password']


class FigoSession(FigoObject):

    """Represents a user-bound connection to the figo connect API and allows access to the users data"""

    def __init__(self, access_token):
        """Creates a FigoSession instance.

        :Parameters:
         - `access_token` - the access token to bind this session to a user
        """
        self.access_token = access_token

    @property
    def accounts(self):
        """An array of `Account` objects, one for each account the user has granted the app access"""

        response = self._query_api("/rest/accounts")
        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return [Account.from_dict(self, account_dict) for account_dict in response['accounts']]

    def get_account(self, account_id):
        """Retrieve a specific account.

        :Parameters:
         - `account_id` - ID of the account to be retrieved

        :Returns:
            `Account` object for the respective account
        """

        response = self._query_api("/rest/accounts/%s" % account_id)
        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return Account.from_dict(self, response)

    def modify_account(self, account_id, name=None, owner=None, preferred_tan_scheme=None, auto_sync=None):
        """Modify an account.

        :Parameters:
         - `account_id` - ID of the account to be modified
         - `name` - Account name
         - `owner` - Account owner
         - `preferred_tan_scheme` - Internal figo Connect TAN scheme ID of the default TAN scheme for this account
         - `auto_sync` - This flag indicates whether the account will be automatically synchronized

         :Returns:
           'Account' object for the updated account
        """

        params = {}
        if name is not None:
            params['name'] = name
        if owner is not None:
            params['owner'] = owner
        if preferred_tan_scheme is not None:
            params['preferred_tan_scheme'] = preferred_tan_scheme
        if auto_sync is not None:
            params['auto_sync'] = auto_sync

        response = self._query_api("/rest/accounts/%s" % account_id, params, method="PUT")
        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return Account.from_dict(self, response)

    def remove_account(self, account_id):
        """Remove an account

        :Parameters:
         - `account_id` - ID of the account to be deleted
        """

        response = self._query_api("/rest/accounts/%s" % account_id, method="DELETE")
        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)

    def get_account_balance(self, account_id):
        """Get balance and account limits.

        :Parameters:
         - `account_id` - ID of the account to be retrieved

        :Returns:
            `AccountBalance` object for the respective account
        """

        response = self._query_api("/rest/accounts/%s/balance" % account_id)
        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return AccountBalance.from_dict(self, response)

    def modify_account_balance(self, account_id, credit_line=None, monthly_spending_limit=None):
        """Modify balance or account limits.

        :Parameters:
         - `account_id` - ID of the account to be modified
         - `credit_line` - Credit line
         - `monthly_spending_limit` - User-defined spending limit

         :Returns:
           'AccountBalance' object for the updated account
        """

        params = {}
        if credit_line is not None:
            params['credit_line'] = credit_line
        if monthly_spending_limit is not None:
            params['monthly_spending_limit'] = monthly_spending_limit

        response = self._query_api("/rest/accounts/%s/balance" % account_id, params, method="PUT")
        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return AccountBalance.from_dict(self, response)

    @property
    def notifications(self):
        """An array of `Notification` objects, one for each registered notification"""

        response = self._query_api("/rest/notifications")
        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return [Notification.from_dict(self, notification_dict) for notification_dict in response['notifications']]

    def get_notification(self, notification_id):
        """Retrieve a specific notification.

        :Parameters:
         - `notification_id` - ID of the notification to be retrieved

        :Returns:
            'Notification' object for the respective notification
        """

        response = self._query_api("/rest/notifications/" + str(notification_id))
        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return Notification.from_dict(self, response)

    def add_notification(self, observe_key, notify_uri, state):
        """Create a new notification.

        :Parameters:
        - `observe_key` - URL describing on what condition this notification is triggered
        - `notify_uri` - URL specifying who and how the notification is delivered
        - `state` - Value passed back transparently when delivering the notification

        :Returns:
            'Notification' object for the newly created notification
        """

        response = self._query_api("/rest/notifications", {'observe_key': observe_key, 'notify_uri': notify_uri, 'state': state}, method="POST")
        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return Notification.from_dict(self, response)

    def modify_notification(self, notification_id, observe_key=None, notify_uri=None, state=None):
        """Modify a notification.

        :Parameters:
         - `notification_id` - ID of the notification to be modified
         - `observe_key` - URL describing on what condition this notification is triggered
         - `notify_uri` - URL specifying who and how the notification is delivered
         - `state` - Value passed back transparently when delivering the notification

        :Returns:
            'Notification' object for the newly created notification
        """

        params = {}
        if observe_key is not None:
            params['observe_key'] = observe_key
        if notify_uri is not None:
            params['notify_uri'] = notify_uri
        if state is not None:
            params['state'] = state

        response = self._query_api("/rest/notifications/" + str(notification_id), params, method="PUT")
        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return Notification.from_dict(self, response)

    def remove_notification(self, notification_id):
        """Remove a notification

        :Parameters:
         - `notification_id` - ID of the notification to be deleted
        """

        response = self._query_api("/rest/notifications/" + str(notification_id), method="DELETE")
        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)

    @property
    def payments(self):
        """Get an array of `Payment` objects, one for each payment of the user over all accounts

        :Returns:
          `List` of Payment objects
        """

        response = self._query_api("/rest/payments")

        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return [Payment.from_dict(self, payment_dict) for payment_dict in response['payments']]

    def get_payments(self, account_id):
        """Get an array of `Payment` objects, one for each payment of the user on the specified account

        :Parameters:
         - `account_id` - ID of the account to be retrieved

        :Returns:
            `List` of Payment objects
        """

        response = self._query_api("/rest/accounts/%s/payments" % (account_id))

        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return [Payment.from_dict(self, payment_dict) for payment_dict in response['payments']]

    def get_payment(self, account_id, payment_id):
        """Get a single `Payment` object

        :Parameters:
         - `account_id` - ID of the account on which the payment is to be found
         - `payment_id` - ID of the payment to be retrieved

        :Returns:
            `Payment` object
        """

        response = self._query_api("/rest/accounts/%s/payments/%s" % (account_id, payment_id))

        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return Payment.from_dict(self, response)

    def add_payment(self, account_id, payment_type, name, account_number, bank_code, amount, purpose, currency='EUR'):
        """Create a new payment

        :Parameters:
         - `account_id` - ID of the account on which the payment is to be created
         - `payment_type` - Payment type
         - `name` - Name of creditor or debtor
         - `account_number` - Account number of creditor or debtor
         - `bank_code` - Bank code of creditor or debtor
         - `amount` - Order amount
         - `purpose` - Purpose text
         - `currency` - Three-character currency code

        :Returns:
            `Payment` object of the newly created payment
        """

        response = self._query_api("/rest/accounts/%s/payments" % (account_id), {'type': payment_type, 'name': name, 'account_number': account_number, 'bank_code': bank_code, 'amount': amount, 'purpose': purpose, 'currency': currency}, "POST")

        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return Payment.from_dict(self, response)

    def modify_payment(self, account_id, payment_id, name=None, account_number=None, bank_code=None, amount=None, purpose=None, currency=None):
        """Modify a payment

        :Parameters:
         - `account_id` - ID of the account on which the payment is to be found
         - `payment_id` - ID of the payment to be modified
         - `name` - Name of creditor or debtor
         - `account_number` - Account number of creditor or debtor
         - `bank_code` - Bank code of creditor or debtor
         - `amount` - Order amount
         - `purpose` - Purpose text
         - `currency` - Three-character currency code

        :Returns:
          'Payment' object for the updated payment
        """

        params = {}
        if name is not None:
            params['name'] = name
        if account_number is not None:
            params['account_number'] = account_number
        if bank_code is not None:
            params['bank_code'] = bank_code
        if amount is not None:
            params['amount'] = amount
        if purpose is not None:
            params['purpose'] = purpose
        if currency is not None:
            params['currency'] = currency

        response = self._query_api("/rest/accounts/%s/payments/%s" % (account_id, payment_id), params, "PUT")

        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return Payment.from_dict(self, response)

    def remove_payment(self, account_id, payment_id):
        """Remove a payment

        :Parameters:
         - `account_id` - ID of the account on which the payment is to be found
         - `payment_id` - ID of the payment to be deleted
        """

        response = self._query_api("/rest/accounts/%s/payments/%s" % (account_id, payment_id), method="DELETE")
        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)

    def submit_payment(self, account_id, payment_id, tan_scheme_id, state, redirect_uri=None):
        """Submit payment to bank server.

        :Parameters:
         - `account_id` - ID of the account on which the payment is to be found
         - `payment_id` - ID of the payment to be submitted
         - `tan_scheme_id` - TAN scheme ID of user-selected TAN scheme
         - `state` - Any kind of string that will be forwarded in the callback response message
         - `redirect_uri` - At the end of the submission process a response will be sent to this callback URL

        :Returns:
            Task token
        """

        params = {'tan_scheme_id': tan_scheme_id, 'state': state}
        if redirect_uri is not None:
            params['redirect_uri'] = redirect_uri

        response = self._query_api("/rest/accounts/%s/payments/%s/submit" % (account_id, payment_id), params, "POST")

        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return response["task_token"]

    @property
    def transactions(self):
        """An array of `Transaction` objects, one for each transaction of the user"""

        response = self._query_api("/rest/transactions")
        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return [Transaction.from_dict(self, transaction_dict) for transaction_dict in response['transactions']]

    def get_transactions(self, account_id):
        """Get an array of `Transaction` objects, one for each transaction of the user

        :Parameters:
         - `account_id` - ID of the account to be retrieved

        :Returns:
            `List` of Transaction objects
        """

        response = self._query_api("/rest/accounts/%s/transactions" % (account_id))

        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return [Transaction.from_dict(self, transaction_dict) for transaction_dict in response['transactions']]

    def get_transaction(self, account_id, transaction_id):
        """Retrieve a specific transaction.

        :Parameters:
         - `account_id` - ID of the account on which the transaction occured
         - `transaction_id` - ID of the transaction to be retrieved

        :Returns:
            a `Transaction` object representing the transaction to be retrieved
        """

        response = self._query_api("/rest/accounts/%s/transactions/%s" % (account_id, transaction_id))

        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return Transaction.from_dict(self, response)

    def get_bank(self, bank_id):
        """Get bank.

        :Parameters:
         - `bank_id` - ID of the bank to be retrieved.

        :Returns:
            a `BankContact` object representing the bank to be retrieved
        """

        response = self._query_api("/rest/banks/%s" % (bank_id))

        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return BankContact.from_dict(self, response)

    def modify_bank(self, bank_id, sepa_creditor_id=None):
        """Modify a bank

        :Parameters:
         - `bank_id` - ID of the bank to be modified.
         - `sepa_creditor_id` - SEPA direct debit creditor ID

         :Returns:
           'BankContact' object for the updated bank
        """

        params = {}
        if sepa_creditor_id is not None:
            params['sepa_creditor_id'] = sepa_creditor_id

        response = self._query_api("/rest/banks/%s" % (bank_id), params, "PUT")

        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return BankContact.from_dict(self, response)

    def remove_bank_pin(self, bank_id):
        """Remove the stored PIN for a bank (if there was one)

        :Parameters:
        - `bank_id` - ID of the bank whose pin should be removed
        """

        response = self._query_api("/rest/banks/%s/remove_pin" (bank_id), method="POST")
        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)

    @property
    def user(self):
        """Get the current figo Account

        :Returns:
          'User' object for the current figo Account
        """

        response = self._query_api("/rest/user")
        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return User.from_dict(self, response)

    def modify_user(self, name=None, send_newsletter=None, language=None, email=None, password=None, new_password=None):
        """Modify figo Account

        :Parameters:
         - `name` - First and last name
         - `send_newsletter` - This flag indicates whether the user has agreed to be contacted by email.
         - `language` - Two-letter code of preferred language
         - `email` - Email address. It must obey the figo username & password policy. If this parameter is set, then the parameter password must be set, too.
         - `password` - Current figo Account password
         - `new_password` - New figo Account password; It must obey the figo username & password policy. If this parameter is set, then the parameter password must be set, too.

        :Returns:
          'User' object for the updated figo Account
        """

        params = {}
        if name is not None:
            params['name'] = name
        if send_newsletter is not None:
            params['send_newsletter'] = send_newsletter
        if language is not None:
            params['language'] = language
        if email is not None:
            params['email'] = email
        if password is not None:
            params['password'] = password
        if new_password is not None:
            params['new_password'] = new_password

        response = self._query_api("/rest/user", params, "PUT")

        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return User.from_dict(self, response)

    def remove_user(self):
        """Delete figo Account"""

        response = self._query_api("/rest/user", method="DELETE")
        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)

    def get_sync_url(self, state, redirect_uri):
        """URL to trigger a synchronisation.

        The user should open this URL in a web browser to synchronize his/her accounts with the respective bank servers. When the process is finished, the user is redirected to the provided URL.

        :Parameters:
         - `state` - String passed on through the complete synchronization process and to the redirect target at the end. It should be used to validated the authenticity of the call to the redirect URL
         - `redirect_uri` - URI the user is redirected to after the process completes

        :Returns:
            the URL to be opened by the user.
        """

        response = self._query_api("/rest/sync", {"state": state, "redirect_uri": redirect_uri}, method="POST")
        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return FigoConnection.API_ENDPOINT + "/task/start?id=" + response['task_token']

    def get_task_start_url(self, task_token):
        """URL for user interface during task processing (e.g. payment submission or account synchronization)

        :Parameters:
         - `task_token` - Task token from the initial request.

        :Returns:
            the URL to be opened by the user.
        """
        return "%s/task/start?id=%s" % (FigoConnection.API_ENDPOINT, task_token)

    def parse_webhook_notification(self, message_body):
        """ parses webhook notification and returns a `WebhookNotification` object

            :Parameters:
            - `message_body` - message body of the webhook message (as string or dict)

            :Returns:
                a WebhookNotification object
        """

        if type(message_body) is not dict:
            message_body = json.loads(message_body)

        notification = WebhookNotification.from_dict(self, message_body)

        data = self._query_api(notification.observe_key)

        if re.match("\/rest\/transactions", notification.observe_key):
            notification.data = [Transaction.from_dict(self, transaction_dict) for transaction_dict in response['transactions']]

        elif re.match("\/rest\/accounts\/(.*)\/transactions", notification.observe_key):
            notification.data = [Transaction.from_dict(self, transaction_dict) for transaction_dict in response['transactions']]

        elif re.match("\/rest\/accounts\/(.*)\/balance", notification.observe_key):
            notification.data = AccountBalance.from_dict(data)

        return notification
