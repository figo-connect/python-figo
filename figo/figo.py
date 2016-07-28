#!/usr/bin/python
# -*- coding:utf-8 -*-

from __future__ import unicode_literals

import base64
import logging
import re
import sys
from time import sleep
import os
from datetime import datetime, timedelta
import json

import requests
from requests.exceptions import SSLError
from requests_toolbelt.adapters.fingerprint import FingerprintAdapter

from .models import *

if sys.version_info[0] > 2:
    import urllib.parse as urllib

    STRING_TYPES = (str)
else:
    import urllib

    STRING_TYPES = (str, unicode)


logger = logging.getLogger(__name__)

VALID_FINGERPRINTS = os.getenv(
    'FIGO_SSL_FINGERPRINT',
    "38:AE:4A:32:6F:16:EA:15:81:33:8B:B0:D8:E4:A6:35:E7:27:F1:07,"
    "DB:E2:E9:15:8F:C9:90:30:84:FE:36:CA:A6:11:38:D8:5A:20:5D:93"
).split(',')


ERROR_MESSAGES = {
    400: {'message': "bad request", 'description': "Bad request"},
    401: {'message': "unauthorized", 'description': "Missing, invalid or expired access token."},
    403: {'message': "forbidden", 'description': "Insufficient permission."},
    404: {'message': "not_found", 'description': "Not found."},
    405: {'message': "method_not_allowed", 'description': "Unexpected request method."},
    503: {'message': "service_unavailable", 'description': "Exceeded rate limit."}

}

USER_AGENT = "python_figo/1.5.4"
API_ENDPOINT = os.getenv('FIGO_API_ENDPOINT',  "https://api.figo.me")


class FigoObject(object):
    """A FigoObject has the ability to communicate with the Figo API."""

    API_SECURE = True
    headers = {}

    def _request_api(self, path, data=None, method="GET"):
        """Helper method for making a REST-compliant API call.

        :Parameters:
         - `path` - path on the server to call
         - `data` - Dictionary of data to send to the server in message body
         - `method` - HTTP verb to use for the request
        :Returns:
            the JSON-parsed result body
        """

        complete_path = API_ENDPOINT + path

        session = requests.Session()
        session.headers.update(self.headers)

        for fingerprint in VALID_FINGERPRINTS:
            session.mount(API_ENDPOINT, FingerprintAdapter(fingerprint))
            try:
                response = session.request(method, complete_path, json=data)
            except SSLError as fingerprint_error:
                logging.warn('Fingerprint "%s"£# was invalid', fingerprint)
            else:
                break
            finally:
                session.close()
        else:
            raise fingerprint_error

        if 200 <= response.status_code < 300:
            if response.text == '':
                return {}
            return response.json()
        elif response.status_code in ERROR_MESSAGES:
            return {'error': ERROR_MESSAGES[response.status_code]}

        logger.warn("Querying the API failed when accessing '%s': %d",
                    complete_path,
                    response.status_code)
        return {'error': {
            'message': "internal_server_error",
            'description': "We are very sorry, but something went wrong"}}

    def _request_with_exception(self, path, data=None, method="GET"):

        response = self._request_api(path, data, method)
        # the check for is_erroneous in response is here to not confuse a task/progress
        # response with an error object
        # FIXME(dennis.lutter): refactor error handling
        if 'error' in response and response["error"] and 'is_erroneous' not in response:
            raise FigoException.from_dict(response)
        else:
            return response

    def _query_api_object(self, model, path, data=None, method="GET", collection_name=None):
        """Helper method using _request_with_exception but encapsulating the result
        as an object."""
        response = self._request_with_exception(path, data, method)
        if response is None:
            return None
        elif collection_name is None:
            return model.from_dict(self, response)
        else:
            return [model.from_dict(self, dict_entry) for dict_entry in response[collection_name]]


class FigoException(Exception):
    """Base class for all exceptions transported via the figo connect API.

    They consist of a code-like `error` and a human readable `error_description`.
    """

    def __init__(self, error, error_description):
        """Create a Exception with a error code and error description."""
        message = u"%s (%s)" % (error_description, error)
        super(FigoException, self).__init__(message)

        # XXX(dennis.lutter): not needed internally but left here for backwards compatibility
        self.error = error
        self.error_description = error_description

    @classmethod
    def from_dict(cls, dictionary):
        """Helper function creating an exception instance from the dictionary returned
        by the server."""
        return cls(dictionary['error']['message'], dictionary['error']['description'])


class FigoPinException(FigoException):
    """This exception is thrown if the wrong pin was submitted to a task. It contains
    information about current state of the task."""

    def __init__(self, country, credentials, bank_code, iban, save_pin):
        """Initialiase an Exception for a wrong PIN which contains information about the task."""
        self.error = "Wrong PIN"
        self.error_description = "You've entered a wrong PIN, please provide a new one."

        self.country = country
        self.credentials = credentials
        self.bank_code = bank_code
        self.iban = iban
        self.save_pin = save_pin

    def __str__(self):
        """String representation of the FigoPinException."""
        return "FigoPinException: %s(%s)" % (repr(self.error_description), repr(self.error))


class FigoConnection(FigoObject):
    """Representing a not user-bound connection to the figo connect API.

    Its main purpose is to let user login via the OAuth2 API.
    """

    def __init__(self, client_id, client_secret, redirect_uri):
        """
        Create a FigoConnection instance.

        :Parameters:
         - `client_id` - the OAuth Client ID as provided by your figo developer contact
         - `client_secret` - the OAuth Client Secret as provided by your figo developer contact
         - `redirect_uri` - the URI the users gets redirected to after the login is finished
         or if he presses cancels
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        basic_auth = "{0}:{1}".format(self.client_id, self.client_secret).encode("ascii")
        basic_auth_encoded = base64.b64encode(basic_auth).decode("utf-8")
        self.headers = {
            'Authorization': "Basic {0}".format(basic_auth_encoded),
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'User-Agent': USER_AGENT}

    def _query_api(self, path, data=None):
        """
        Helper method for making a OAuth2-compliant API call.

        :Parameters:
         - `path` - path on the server to call
         - `data` - Dictionary of data to send to the server in message body

        :Returns:
            the JSON-parsed result body
        """

        return self._request_api(path=path, data=data)

    def login_url(self, scope, state):
        """The URL a user should open in his/her web browser to start the login process.

        When the process is completed, the user is redirected to the URL provided to
        the constructor and passes on an authentication code. This code can be converted into
        an access token for data access.

        :Parameters:
         - `scope` - Scope of data access to ask the user for, e.g. `accounts=ro`
         - `state` - String passed on through the complete login process and to the redirect
         target at the end. It should be used to validated the authenticity of the
         call to the redirect URL

        :Returns:
            the URL of the first page of the login process
        """
        return (("https://" if self.API_SECURE else "http://") +
                API_ENDPOINT +
                "/auth/code?" +
                urllib.urlencode(
                    {'response_type': 'code',
                     'client_id': self.client_id,
                     'redirect_uri': self.redirect_uri,
                     'scope': scope, 'state': state}
                ))

    def convert_authentication_code(self, authentication_code):
        """
        Convert the authentication code received as result of the login process into an
        access token usable for data access.

        :parameters:
         - `authentication_code` - the code received as part of the call to the redirect
         URL at the end of the logon process

        :returns:
            Dictionary with the following keys:
             - `access_token` - the access token for data access. You can pass it into
             `FigoConnection.open_session` to get a FigoSession and access the users data
             - `refresh_token` - if the scope contained the `offline` flag, also a
             refresh token is generated. It can be used to generate new access tokens,
             when the first one has expired.
             - `expires` - absolute time the access token expires
        """
        if authentication_code[0] != "O":
            raise Exception("Invalid authentication code")

        response = self._request_api(
            "/auth/token",
            data={'code': authentication_code,
                  'redirect_uri': self.redirect_uri,
                  'grant_type': 'authorization_code'},
            method="POST")

        if 'error' in response:
            raise FigoException.from_dict(response)

        return {'access_token': response['access_token'],
                'refresh_token': response['refresh_token'] if 'refresh_token' in response else None,
                'expires': datetime.now() + timedelta(seconds=response['expires_in'])}

    def credential_login(self, username, password):
        """
        Return a Token dictionary which tokens are used for further API actions.

        :Parameters:
            -   'username' - Figo username
            -   'password' - Figo password

        :Return:
            Dictionary which contains an access token and a refresh token.
        """
        response = self._request_api(
            "/auth/token",
            data={"grant_type": "password",
                  "username": username,
                  "password": password},
            method="POST")

        if 'error' in response:
            raise FigoException.from_dict(response)

        return {'access_token': response['access_token'],
                'refresh_token': response['refresh_token'] if 'refresh_token' in response else None,
                'expires': datetime.now() + timedelta(seconds=response['expires_in'])}

    def convert_refresh_token(self, refresh_token):
        """Convert a refresh token (granted for offline access and returned by
        `convert_authentication_code`) into an access token usable for data access.

        :Parameters:
         - `refresh_token` - refresh token returned by `convert_authentication_code`

        :Returns:
            Dictionary with the following keys:
             - `access_token` - the access token for data access. You can pass it into
             `FigoConnection.open_session` to get a FigoSession and access the users data
             - `expires` - absolute time the access token expires
        """
        if refresh_token[0] != "R":
            raise Exception("Invalid refresh token")

        response = self._request_api("/auth/token", data={
            'refresh_token': refresh_token, 'redirect_uri': self.redirect_uri,
            'grant_type': 'refresh_token'}, method="POST")
        if 'error' in response:
            raise FigoException.from_dict(response)

        return {'access_token': response['access_token'],
                'expires': datetime.now() + timedelta(seconds=response['expires_in'])}

    def revoke_token(self, token):
        """
        Revoke a granted access or refresh token and thereby invalidate it.

        Note: this action has immediate effect, i.e. you will not be able use that
        token anymore after this call.

        :Parameters:
         - `token` - access or refresh token to be revoked
        """
        response = self._request_api("/auth/revoke?" + urllib.urlencode({'token': token}))
        if 'error' in response:
            raise FigoException.from_dict(response)

    def add_user(self, name, email, password, language='de'):
        """
        Create a new figo Account.

        :Parameters:
        - `name` - First and last name
        - `email` - Email address; It must obey the figo username & password policy
        - `password` - New figo Account password; It must obey the figo username & password policy
        - `language` - Two-letter code of preferred language

        :Returns:
            Auto-generated recovery password.
        """
        response = self._request_api(
            path="/auth/user",
            data={'name': name,
                  'email': email,
                  'password': password,
                  'language': language,
                  'affiliate_client_id': self.client_id},
            method="POST")

        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return response['recovery_password']

    def add_user_and_login(self, name, email, password, language='de'):
        """
        Create a new figo account and get a session token for the new account.

        :Parameters:
        - `name` - First and last name
        - `email` - Email address; It must obey the figo username & password policy
        - `password` - New figo Account password; It must obey the figo
        username & password policy
        - `language` - Two-letter code of preferred language
        - `send_newsletter` - This flag indicates whether the user has agreed to be
        contacted by email

        :Returns:
            Token dictionary for further API access
        """
        self.add_user(name, email, password, language)
        return self.credential_login(email, password)


class FigoSession(FigoObject):
    """Represents a user-bound connection to the figo connect API and allows access to
    the users data."""

    def __init__(self, access_token, sync_poll_retry=20):
        """Create a FigoSession instance.

        :Parameters:
         - `access_token` - the access token to bind this session to a user
        """
        self.access_token = access_token
        self.headers = {
            'Authorization': "Bearer %s" % self.access_token,
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'User-Agent': USER_AGENT}
        self.sync_poll_retry = 20

    @property
    def accounts(self):
        """An array of `Account` objects, one for each account the user has granted
        the app access."""
        return self._query_api_object(Account, "/rest/accounts", collection_name="accounts")

    def get_account(self, account_id):
        """
        Retrieve a specific account.

        :Parameters:
         - `account_id` - ID of the account to be retrieved

        :Returns:
            `Account` object for the respective account
        """
        return self._query_api_object(Account, "/rest/accounts/%s" % account_id)

    def add_account(self, country, credentials, bank_code=None, iban=None, save_pin=False):
        """
        Add an account.

        :Parameters:
        - `bank_code` - bank code of the bank to add
        - `country` - country code of the bank to add
        - `credentials` - list of credentials needed for bank login

        :Returns:
         A task token for the account creation task
        """
        data = {}
        if iban is not None:
            data = {"iban": iban, "country": country, "credentials": credentials,
                    "save_pin": save_pin}
        elif bank_code is not None:
            data = {"bank_code": bank_code, "country": country, "credentials": credentials,
                    "save_pin": save_pin}
        return self._query_api_object(TaskToken, "/rest/accounts", data, "POST")

    def add_account_and_sync(self, country, credentials, bank_code=None, iban=None, save_pin=False):
        """
        Add a bank account to the Figo user and start syncing it.

        bank_code or iban has to be set.

        :Parameters:
        - `bank_code` - bank code of the bank to add
        - `country` - country code of the bank to add
        - `credentials` - list of credentials needed for bank login

        :Returns:
         State of the sync task.
        """
        task_token = self.add_account(country, credentials, bank_code, iban, save_pin)
        for _ in range(self.sync_poll_retry):
            task_state = self.get_task_state(task_token)
            logger.info('task message: %s', task_state.message)
            logger.debug('task "%s"', task_state)
            if task_state.is_ended or task_state.is_erroneous:
                break
            sleep(0.5)
        else:
            raise FigoException(
                'could not sync',
                'task was not finished after {0} tries'.format(self.sync_poll_retry)
            )

        if task_state.is_erroneous:
            if any([msg in task_state.message for msg in ["Zugangsdaten", "credentials"]]):
                raise FigoPinException(country, credentials, bank_code, iban, save_pin)
            raise FigoException("", task_state.message)
        return task_state

    def add_account_and_sync_with_new_pin(self, pin_exception, new_pin):
        """
        Provide a new pin if the sync task was erroneous because of a wrong pin.

        :Parameters:
            - 'pin_exception'   -   Exception of the sync task for which a new pin will be provided
            - 'new_pin'         -   New pin for the sync task

        :Returns:
            The state of the sync task. If the pin was wrong a FigoPinException is thrown
        """
        pin_exception.credentials[1] = new_pin
        return self.add_account_and_sync(pin_exception.country,
                                         pin_exception.credentials,
                                         pin_exception.bank_code,
                                         pin_exception.iban,
                                         pin_exception.save_pin,
                                         )

    def modify_account(self, account):
        """
        Modify an account.

        :Parameters:
         - `account` - the modified account to be saved

        :Returns:
           'Account' object for the updated account returned by server
        """
        return self._query_api_object(Account, "/rest/accounts/%s" % account.account_id,
                                      account.dump(), "PUT")

    def remove_account(self, account_or_account_id):
        """
        Remove an account.

        :Parameters:
         - `account_or_account_id` - account to be removed or its ID
        """
        if isinstance(account_or_account_id, STRING_TYPES):
            self._request_with_exception("/rest/accounts/%s" % account_or_account_id,
                                           method="DELETE")
        else:
            self._request_with_exception("/rest/accounts/%s" % account_or_account_id.account_id,
                                           method="DELETE")

        return None

    def get_account_balance(self, account_or_account_id):
        """
        Get balance and account limits.

        :Parameters:
         - `account_or_account_id` - account to be removed or its ID

        :Returns:
            `AccountBalance` object for the respective account
        """
        if isinstance(account_or_account_id, Account):
            return self._query_api_object(
                AccountBalance,
                "/rest/accounts/%s/balance" % account_or_account_id.account_id)
        else:
            return self._query_api_object(
                AccountBalance,
                "/rest/accounts/%s/balance" % account_or_account_id)

    def modify_account_balance(self, account_or_account_id, account_balance):
        """
        Modify balance or account limits.

        :Parameters:
         - `account_or_account_id` - account to be removed or its ID
         - `account_balance` - modified AccountBalance object to be saved

         :Returns:
           'AccountBalance' object for the updated account as returned by the server
        """
        if isinstance(account_or_account_id, Account):
            return self._query_api_object(
                AccountBalance,
                "/rest/accounts/%s/balance" % account_or_account_id.account_id,
                account_balance.dump(), "PUT")
        else:
            return self._query_api_object(
                AccountBalance,
                "/rest/accounts/%s/balance" % account_or_account_id,
                account_balance.dump(), "PUT")

    def get_supported_payment_services(self, country_code):
        """
        Return a list of supported credit cards an other payment services.

        A fake bank code is used for identification

        :Parameters:
            - 'country_code'    -   country code of the requested payment services
        :Returns:
            A list of Service objects
        """
        services = self._request_with_exception("/rest/catalog/services/%s" % country_code)[
            "services"]
        return [Service.from_dict(self, service) for service in services]

    def get_login_settings(self, country_code, item_id):
        """
        Return the login settings of a bank or service.

        :Parameters:
            - 'country_code'    -   country code of the requested bank or service
            - 'item_id'         -   bank code or fake bank code of the requested bank or service
        :Returns:
            A LoginSettings object which contains information which are needed for
            logging in to the bank or service.
        """
        return self._query_api_object(LoginSettings,
                                      "/rest/catalog/banks/%s/%s" % (country_code, item_id))

    def set_account_sort_order(self, accounts):
        """
        Set the sort order of the user's accounts.

        :Parameters:
            - accounts - List of Accounts
        :Returns:
            empty response if successful
        """
        data = {"accounts": [{"account_id": account.account_id} for account in accounts]}
        return self._request_with_exception("/rest/accounts", data, "POST")

    @property
    def notifications(self):
        """An array of `Notification` objects, one for each registered notification."""
        return self._query_api_object(Notification, "/rest/notifications",
                                      collection_name="notifications")

    def get_notification(self, notification_id):
        """
        Retrieve a specific notification.

        :Parameters:
         - `notification_id` - ID of the notification to be retrieved

        :Returns:
            'Notification' object for the respective notification
        """
        return self._query_api_object(Notification, "/rest/notifications/" + str(notification_id))

    def add_notification(self, notification):
        """
        Create a new notification.

        :Parameters:
        - `notification` - new notification to be created. It should have no notification_id set

        :Returns:
            'Notification' object for the newly created notification
        """
        return self._query_api_object(Notification, "/rest/notifications", notification.dump(),
                                      "POST")

    def modify_notification(self, notification):
        """
        Modify a notification.

        :Parameters:
         - `notification` - modified notification object to be saved

        :Returns:
            'Notification' object for the modified notification
        """
        return self._query_api_object(Notification,
                                      "/rest/notifications/" + notification.notification_id,
                                      notification.dump(), "PUT")

    def remove_notification(self, notification_or_notification_id):
        """Remove a notification.

        :Parameters:
         - `notification_or_notification_id` - notification to be removed or its ID
        """
        if isinstance(notification_or_notification_id, STRING_TYPES):
            self._request_with_exception("/rest/notifications/" + notification_or_notification_id,
                                           method="DELETE")
        else:
            self._request_with_exception(
                "/rest/notifications/" + notification_or_notification_id.notification_id,
                method="DELETE")
        return None

    @property
    def payments(self):
        """
        Get an array of `Payment` objects, one for each payment of the user over all accounts.

        :Returns:
          `List` of Payment objects
        """
        return self._query_api_object(Payment, "/rest/payments", collection_name="payments")

    def get_payments(self, account_or_account_id):
        """Get an array of `Payment` objects, one for each payment of the user on
        the specified account.

        :Parameters:
         - `account_or_account_id` - account to be removed or its ID

        :Returns:
            `List` of Payment objects
        """
        if isinstance(account_or_account_id, Account):
            return self._query_api_object(Payment, "/rest/accounts/%s/payments" % (
                account_or_account_id.account_id), collection_name="payments")
        else:
            return self._query_api_object(Payment,
                                          "/rest/accounts/%s/payments" % account_or_account_id,
                                          collection_name="payments")

    def get_payment(self, account_or_account_id, payment_id):
        """
        Get a single `Payment` object.

        :Parameters:
         - `account_or_account_id` - account to be removed or its ID
         - `payment_id` - ID of the payment to be retrieved

        :Returns:
            `Payment` object
        """
        if isinstance(account_or_account_id, Account):
            return self._query_api_object(Payment, "/rest/accounts/%s/payments/%s" % (
                account_or_account_id.account_id, payment_id))
        else:
            return self._query_api_object(Payment, "/rest/accounts/%s/payments/%s" % (
                account_or_account_id, payment_id))

    def add_payment(self, payment):
        """
        Create a new payment.

        :Parameters:
         - `payment` - payment to be created. It should not have its payment_id set.

        :Returns:
            `Payment` object of the newly created payment as returned by the server
        """
        return self._query_api_object(Payment, "/rest/accounts/%s/payments" % payment.account_id,
                                      payment.dump(), "POST")

    def modify_payment(self, payment):
        """Modify a payment.

        :Parameters:
         - `payment` - modified payment object to be modified

        :Returns:
          'Payment' object for the updated payment
        """
        return self._query_api_object(Payment, "/rest/accounts/%s/payments/%s" % (
            payment.account_id, payment.payment_id), payment.dump(), "PUT")

    def remove_payment(self, payment):
        """Remove a payment.

        :Parameters:
         - `payment` -  payment to be removed
        """
        self._request_with_exception(
            "/rest/accounts/%s/payments/%s" % (payment.account_id, payment.payment_id),
            method="DELETE")
        return None

    def submit_payment(self, payment, tan_scheme_id, state, redirect_uri=None):
        """
        Submit payment to bank server.

        :Parameters:
         - `payment` - payment to be submitted
         - `tan_scheme_id` - TAN scheme ID of user-selected TAN scheme
         - `state` - Any kind of string that will be forwarded in the callback response message
         - `redirect_uri` - At the end of the submission process a response will
         be sent to this callback URL

        :Returns:
            the URL to be opened by the user for the TAN process
        """
        params = {'tan_scheme_id': tan_scheme_id, 'state': state}
        if redirect_uri is not None:
            params['redirect_uri'] = redirect_uri

        response = self._request_with_exception(
            "/rest/accounts/%s/payments/%s/submit" % (payment.account_id, payment.payment_id),
            params, "POST")

        if response is None:
            return None
        else:
            return (("https" if self.API_SECURE else "http") +
                    "://" + API_ENDPOINT + "/task/start?id=" +
                    response["task_token"])

    @property
    def payment_proposals(self):
        """List of payment proposal object."""
        return self.get_payment_proposals()

    def get_payment_proposals(self):
        """Provide a address book-like list of proposed wire transfer partners."""
        response = self._request_with_exception("/rest/address_book")
        return [PaymentProposal.from_dict(self, payment_proposal) for payment_proposal in response]

    def start_task(self, task_token_obj):
        """
        Start the given task.

        :Parameters:
            - task_token_obj    -   TaskToken object of the task to start
        """
        return self._request_with_exception("/task/start?id=%s" % task_token_obj.task_token)

    def get_task_state(self, task_token, **kwargs):
        """Return the progress of the given task. The kwargs are used to submit additional
        content for the task.

        :Parameters:
        - `pin` - Submit PIN. If this parameter is set, then the parameter save_pin must be
        set, too.
        - `continue` - This flag signals to continue after an error condition or to skip a
        PIN or challenge-response entry
        - `save_pin` - This flag indicates whether the user has chosen to save the PIN on
        the figo Connect server
        - `response` - Submit response to challenge.

        :Returns:
        A TaskState object which indicates the current status of the queried task
        """
        logger.debug('Geting task state for: %s', task_token)
        data = {"id": task_token.task_token}
        if "pin" in kwargs:
            data["pin"] = kwargs["pin"]
        if "continue" in kwargs:
            data["continue"] = kwargs["continue"]
        if "save_pin" in kwargs:
            data["save_pin"] = kwargs["save_pin"]
        if "response" in kwargs:
            data["response"] = kwargs["response"]
        return self._query_api_object(
            TaskState,
            "/task/progress?id=%s" % task_token.task_token,
            data,
            "POST",
        )

    def cancel_task(self, task_token_obj):
        """Cancel a task if possible.

        :Parameters:
            - task_token_obj    -   TaskToken object of the task to cancel
        """
        return self._request_with_exception(
            path="/task/cancel?id=%s" % task_token_obj.task_token,
            data={"id": task_token_obj.task_token},
            method="POST")

    def start_process(self, process_token):
        """
        Start the given process.

        :Parameters:
            - process_token -   ProcessToken object for the process to start
        """
        return self._request_with_exception("/process/start?id=%s" % process_token.process_token)

    def create_process(self, process):
        """
        Create a new process to be executed by the user Returns a process token.

        :Parameters:
            - process   -   Process object which will be sent to the API
        """
        return self._query_api_object(ProcessToken, "/client/process", process.dump(), "POST")

    @property
    def transactions(self):
        """An array of `Transaction` objects, one for each transaction of the user."""
        return self._query_api_object(Transaction, "/rest/transactions",
                                      collection_name="transactions")

    def get_transactions(self, account_id=None, since=None, count=1000, offset=0,
                         include_pending=False):
        """Get an array of `Transaction` objects, one for each transaction of the user.

        :Parameters:
         - `account_id` - ID of the account for which to list the transactions
         - `since` - this parameter can either be a transaction ID or a date
         - `count` - limit the number of returned transactions
         - `offset` - which offset into the result set should be used to determine the
         first transaction to return (useful in combination with count)
         - `include_pending` - this flag indicates whether pending transactions should
         be included in the response; pending transactions are always included as a
         complete set, regardless of the `since` parameter

        :Returns:
            `List` of Transaction objects
        """
        params = {'count': count, 'offset': offset,
                  'include_pending': ("1" if include_pending else "0")}
        if since is not None:
            params['since'] = since

        return self._query_api_object(Transaction, (
            "/rest/transactions?" if account_id is None else (
                "/rest/accounts/%s/transactions?" % account_id)) + urllib.urlencode(params),
                                      collection_name="transactions")

    def get_transaction(self, account_or_account_id, transaction_id):
        """
        Retrieve a specific transaction.

        :Parameters:
         - `account_or_account_id` - account to be removed or its ID
         - `transaction_id` - ID of the transaction to be retrieved

        :Returns:
            a `Transaction` object representing the transaction to be retrieved
        """
        if isinstance(account_or_account_id, Account):
            return self._query_api_object(Transaction, "/rest/accounts/%s/transactions/%s" % (
                account_or_account_id.account_id, transaction_id))
        else:
            return self._query_api_object(Transaction, "/rest/accounts/%s/transactions/%s" % (
                account_or_account_id, transaction_id))

    # Method added by Fincite (http://fincite.de) on 06/03/2015
    @property
    def securities(self):
        """An array of `Security` objects, one for each transaction of the user."""
        return self._query_api_object(Security, "/rest/securities", collection_name="securities")

    # Method added by Fincite (http://fincite.de) on 06/03/2015
    def get_securities(self, account_id=None, since=None, count=1000, offset=0, accounts=None):
        """Get an array of `Security` objects, one for each security of the user.

        :Parameters:
         - `account_id` - ID of the account for which to list the securities
         - `since` - this parameter can either be a transaction ID or a date
         - `count` - limit the number of returned transactions
         - `offset` - which offset into the result set should be used to determine the first
         transaction to return (useful in combination with count)
         - `accounts` - if retrieving the securities for all accounts, filter the
         securities to be only from these accounts

        :Returns:
            `List` of Security objects
        """
        params = {'count': count, 'offset': offset}
        if accounts is not None and type(accounts) == list:
            params['accounts'] = ",".join(accounts)

        if since is not None:
            params['since'] = since

        return self._query_api_object(Security, ("/rest/securities?" if account_id is None else (
            "/rest/accounts/%s/securities?" % account_id)) + urllib.urlencode(params),
                                      collection_name="securities")

    # Method added by Fincite (http://fincite.de) on 06/03/2015
    def get_security(self, account_or_account_id, security_id):
        """
        Retrieve a specific security.

        :Parameters:
         - `account_or_account_id` - account to be removed or its ID
         - `security_id` - ID of the security to be retrieved

        :Returns:
            a `Security` object representing the transaction to be retrieved
        """
        if isinstance(account_or_account_id, Account):
            return self._query_api_object(Security, "/rest/accounts/%s/securities/%s" % (
                account_or_account_id.account_id, security_id))
        else:
            return self._query_api_object(Security, "/rest/accounts/%s/securities/%s" % (
                account_or_account_id, security_id))

    def modify_security(self, account_or_account_id, security_or_security_id, visited=None):
        """
        Modify a specific security.

        :Parameters:
         - `account_or_account_id` - account to be removed or its ID
         - `securities_or_security_id` - Security or its ID to be modified
         - `visited` - new value of the visited field for the security

        :Returns:
            Nothing if the request was successful
        """
        if isinstance(account_or_account_id, Account) and isinstance(security_or_security_id,
                                                                     Security):
            return self._request_with_exception("/rest/accounts/%s/securities/%s" % (
                account_or_account_id.account_id, security_or_security_id.security_id),
                                                  {"visited": visited}, "PUT")
        else:
            return self._request_with_exception("/rest/accounts/%s/securities/%s" % (
                account_or_account_id, security_or_security_id), {"visited": visited}, "PUT")

    def modify_account_securities(self, account_or_account_id, visited=None):
        """
        Modify all securities of an account.

        :Parameters:
         - `account_or_account_id` - account to be removed or its ID
         - `visited` - new value of the visited field for the security

        :Returns:
            Nothing if the request was successful
        """
        if isinstance(account_or_account_id, Account):
            return self._request_with_exception(
                "/rest/accounts/%s/securities" % account_or_account_id.account_id,
                {"visited": visited}, "PUT")
        else:
            return self._request_with_exception(
                "/rest/accounts/%s/securities" % account_or_account_id, {"visited": visited},
                "PUT")

    def modify_user_securities(self, visited=None):
        """
        Modify all securities from the current user.

        :Parameters:
        - `visited` - new value of the visited field for the security

        :Returns:
            Nothing if the request was successful
        """
        return self._request_with_exception("/rest/securities", {"visited": visited}, "PUT")

    def modify_transaction(self, account_or_account_id, transaction_or_transaction_id,
                           visited=None):
        """
        Modify a specific transaction.

        :Parameters:
         - `account_or_account_id` - account to be removed or its ID
         - `transaction_or_transaction_id` - Transactions or its ID to be modified
         - `visited` - new value of the visited field for the transaction

        :Returns:
            Nothing if the request was successful
        """
        if isinstance(account_or_account_id, Account) and isinstance(transaction_or_transaction_id,
                                                                     Transaction):
            return self._query_api_object(Transaction, "/rest/accounts/%s/transactions/%s" % (
                account_or_account_id.account_id, transaction_or_transaction_id.transaction_id),
                                          {"visited": visited}, "PUT")
        else:
            return self._query_api_object(Transaction, "/rest/accounts/%s/transactions/%s" % (
                account_or_account_id, transaction_or_transaction_id), {"visited": visited}, "PUT")

    def modify_account_transactions(self, account_or_account_id, visited=None):
        """
        Modify all transactions of a specific account.

        :Parameters:
         - `account_or_account_id` - account to be removed or its ID
         - `visited` - new value of the visited field for the transactions

        :Returns:
            Nothing if the request was successful
        """
        if isinstance(account_or_account_id, Account):
            return self._request_with_exception(
                "/rest/accounts/%s/transactions" % account_or_account_id.account_id,
                {"visited": visited}, "PUT")
        else:
            return self._request_with_exception(
                "/rest/accounts/%s/transactions" % account_or_account_id, {"visited": visited},
                "PUT")

    def modify_user_transactions(self, visited=None):
        """Modify all transactions of the current user.

        :Parameters:
         - `visited` - new value of the visited field for the transactions

        :Returns:
            Nothing if the request was successful
        """
        return self._request_with_exception("/rest/transactions", {"visited": visited}, "PUT")

    def delete_transaction(self, account_or_account_id, transaction_or_transaction_id):
        """
        Delete a specific transaction.

        :Parameters:
         - `account_or_account_id` - account to be removed or its ID
         - `transaction_or_transaction_id` - Transaction or its ID to be modified

        :Returns:
            Nothing if the request was successful
        """
        if isinstance(account_or_account_id, Account) and isinstance(transaction_or_transaction_id,
                                                                     Transaction):
            return self._request_with_exception("/rest/accounts/%s/transactions/%s" % (
            account_or_account_id.account_id, transaction_or_transaction_id.transaction_id),
                                                  method="DELETE")
        else:
            return self._request_with_exception("/rest/accounts/%s/transactions/%s" % (
            account_or_account_id, transaction_or_transaction_id), method="DELETE")

    def get_bank(self, bank_id):
        """
        Get bank.

        :Parameters:
         - `bank_id` - ID of the bank to be retrieved.

        :Returns:
            a `BankContact` object representing the bank to be retrieved
        """
        return self._query_api_object(BankContact, "/rest/banks/%s" % bank_id)

    def modify_bank(self, bank):
        """Modify a bank.

        :Parameters:
         - `bank` - modified bank object to be saved

         :Returns:
           'BankContact' object for the updated bank
        """
        return self._query_api_object(BankContact, "/rest/banks/%s" % bank.bank_id, bank.dump(),
                                      "PUT")

    def remove_bank_pin(self, bank_or_bank_id):
        """
        Remove the stored PIN for a bank (if there was one).

        :Parameters:
        - `bank_or_bank_id` - bank whose pin should be removed or its ID
        """
        if isinstance(bank_or_bank_id, STRING_TYPES):
            self._request_with_exception("/rest/banks/%s/remove_pin" % bank_or_bank_id,
                                           method="POST")
        else:
            self._request_with_exception("/rest/banks/%s/remove_pin" % bank_or_bank_id.bank_id,
                                           method="POST")
        return None

    @property
    def user(self):
        """Get the current figo Account.

        :Returns:
          'User' object for the current figo Account
        """
        return self._query_api_object(User, "/rest/user")

    def modify_user(self, user):
        """Modify figo Account.

        :Parameters:
         - `user` - modified user object to be saved

        :Returns:
          'User' object for the updated figo Account
        """
        return self._query_api_object(User, "/rest/user", user.dump(), "PUT")

    def remove_user(self):
        """Delete figo Account."""
        self._request_with_exception("/rest/user", method="DELETE")
        return None

    def get_sync_url(self, state, redirect_uri):
        """
        URL to trigger a synchronisation.

        The user should open this URL in a web browser to synchronize his/her accounts with
        the respective bank servers. When the process is finished, the user is
        redirected to the provided URL.

        :Parameters:
         - `state` - String passed on through the complete synchronization process and to
         the redirect target at the end. It should be used to validated the authenticity
         of the call to the redirect URL
         - `redirect_uri` - URI the user is redirected to after the process completes

        :Returns:
            the URL to be opened by the user.
        """
        response = self._request_with_exception("/rest/sync",
                                                  {"state": state, "redirect_uri": redirect_uri},
                                                  method="POST")
        if response is None:
            return None
        else:
            return (("https://" if self.API_SECURE else "http://") +
                    API_ENDPOINT + "/task/start?id=" +
                    response['task_token'])

    def parse_webhook_notification(self, message_body):
        """
        Parse a webhook notification and get a WebhookNotification object.

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
            notification.data = [Transaction.from_dict(self, transaction_dict) for transaction_dict
                                 in data['transactions']]

        elif re.match("\/rest\/accounts\/(.*)\/transactions", notification.observe_key):
            notification.data = [Transaction.from_dict(self, transaction_dict) for transaction_dict
                                 in data['transactions']]

        elif re.match("\/rest\/accounts\/(.*)\/balance", notification.observe_key):
            notification.data = AccountBalance.from_dict(data)

        return notification
