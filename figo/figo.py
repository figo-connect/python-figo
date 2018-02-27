#!/usr/bin/python
# -*- coding:utf-8 -*-

from __future__ import unicode_literals
from __future__ import absolute_import

import base64
import json
import logging
import re
import sys

from datetime import datetime
from datetime import timedelta
from requests.exceptions import SSLError
from requests import Session
from requests_toolbelt.adapters.fingerprint import FingerprintAdapter
from time import sleep

from figo.credentials import CREDENTIALS
from figo.models import Account
from figo.models import AccountBalance
from figo.models import BankContact
from figo.models import LoginSettings
from figo.models import Notification
from figo.models import Payment
from figo.models import PaymentProposal
from figo.models import Security
from figo.models import Service
from figo.models import TaskState
from figo.models import TaskToken
from figo.models import Transaction
from figo.models import User
from figo.models import WebhookNotification
from figo.version import __version__


if sys.version_info[0] > 2:
    import urllib.parse as urllib
else:
    import urllib

logger = logging.getLogger(__name__)


ERROR_MESSAGES = {
    400: {
        'message': "bad request",
        'description': "Bad request",
        'code': 90000,
    },
    401: {
        'message': "unauthorized",
        'description': "Missing, invalid or expired access token.",
        'code': 90000,
    },
    403: {
        'message': "forbidden",
        'description': "Insufficient permission.",
        'code': 90000,
    },
    404: {
        'message': "not_found",
        'description': "Not found.",
        'code': 90000,
    },
    405: {
        'message': "method_not_allowed",
        'description': "Unexpected request method.",
        'code': 90000,
    },
    503: {
        'message': "service_unavailable",
        'description': "Exceeded rate limit.",
        'code': 90000,
    },
}


class FigoObject(object):
    """A FigoObject has the ability to communicate with the Figo API."""

    def __init__(self,
                 api_endpoint=CREDENTIALS['api_endpoint'],
                 fingerprints=CREDENTIALS['ssl_fingerprints'],
                 language=None):
        """Create a FigoObject instance.

        Args:
            api_endpoint (str) - base URI of the server to call
            fingerprints ([str]) - list of the server's SSL fingerprints
            language (str) - language for HTTP request header
        """
        self.headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'User-Agent': "python_figo/{0}".format(__version__),
        }
        self.language = language
        self.api_endpoint = api_endpoint
        self.fingerprints = fingerprints.split(',')

    def _request_api(self, path, data=None, method="GET"):
        """Helper method for making a REST-compliant API call.

        Args:
            path: path on the server to call
            data: dictionary of data to send to the server in message body
            method: - HTTP verb to use for the request

        Returns:
            the JSON-parsed result body
        """

        complete_path = self.api_endpoint + path

        session = Session()
        session.headers.update(self.headers)

        for fingerprint in self.fingerprints:
            session.mount(self.api_endpoint, FingerprintAdapter(fingerprint.lower()))
            try:
                response = session.request(method, complete_path, json=data)
            except SSLError:
                logging.warn('Fingerprint "%s" was invalid', fingerprint)
            else:
                break
            finally:
                session.close()
        else:
            raise SSLError


        if 200 <= response.status_code < 300 or self._has_error(response.json()):
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
            'description': "We are very sorry, but something went wrong",
            'code': 90000}}

    def _request_with_exception(self, path, data=None, method="GET"):
        response = self._request_api(path, data, method)
        # the check for is_erroneous in response is here to not confuse a task/progress
        # response with an error object
        if self._has_error(response) and 'is_erroneous' not in response:
            raise FigoException.from_dict(response)
        else:
            return response

    def _has_error(self, response):
        return 'error' in response and response["error"]

    def _query_api_object(self, model, path, data=None, method="GET", collection_name=None):
        """
        Helper method using _request_with_exception but encapsulating the result as an object.
        """
        response = self._request_with_exception(path, data, method)
        if response is None:
            return None
        elif collection_name is None:
            return model.from_dict(self, response)
        else:
            return [model.from_dict(self, dict_entry) for dict_entry in response[collection_name]]

    @property
    def language(self):
        return self.headers.get('Accept-Language')

    @language.setter
    def language(self, lang):
        if lang:
            self.headers['Accept-Language'] = lang
        elif self.headers.get('Accept-Language'):
            del self.headers['Accept-Language']


class FigoException(Exception):
    """Base class for all exceptions transported via the figo connect API.

    They consist of a code-like `error` and a human readable `error_description`.
    """

    def __init__(self, error, error_description, code=None):
        """Create a Exception with a error code and error description."""
        super(FigoException, self).__init__()

        # XXX(dennis.lutter): not needed internally but left here for backwards compatibility
        self.error = error
        self.error_description = error_description
        self.code = code

    def __str__(self):
        """String representation of the FigoException."""
        return "FigoException: {} ({})".format(self.error_description, self.error)

    @classmethod
    def from_dict(cls, dictionary):
        """
        Helper function creating an exception instance from the dictionary returned by the server.
        """
        return cls(dictionary['error'].get('message'),
                   dictionary['error'].get('description'),
                   dictionary['error'].get('code'))


class FigoPinException(FigoException):
    """
    This exception is thrown if the wrong pin was submitted to a task. It contains information about
    current state of the task.
    """

    def __init__(self, country, credentials, bank_code, iban, save_pin,
                 error="Wrong PIN",
                 error_description="You've entered a wrong PIN, please provide a new one.",
                 code=None):
        """Initialiase an Exception for a wrong PIN which contains information about the task."""
        super(FigoPinException, self).__init__(error, error_description, code)

        self.country = country
        self.credentials = credentials
        self.bank_code = bank_code
        self.iban = iban
        self.save_pin = save_pin

    def __str__(self):
        """String representation of the FigoPinException."""
        return "FigoPinException: {}({})".format(self.error_description, self.error)


class FigoConnection(FigoObject):
    """Representing a not user-bound connection to the figo connect API.

    Its main purpose is to let user login via the OAuth2 API.
    """

    def __init__(self, client_id, client_secret, redirect_uri,
                 api_endpoint=CREDENTIALS['api_endpoint'],
                 fingerprints=CREDENTIALS['ssl_fingerprints'],
                 language=None):
        """
        Create a FigoConnection instance.

        Args:
            client_id (str) - the OAuth Client ID as provided by your figo developer contact
            client_secret (str) - the OAuth Client Secret as provided by your figo developer contact
            redirect_uri (str) - the URI the users gets redirected to after the login is finished
                            or if they press `cancel`
            api_endpoint (str) - base URI of the server to call
            fingerprints ([str]) - list of the server's SSL fingerprints
            language (str) - language for HTTP request header
        """
        super(FigoConnection, self).__init__(api_endpoint=api_endpoint, fingerprints=fingerprints,
                                             language=language)

        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        basic_auth = "{0}:{1}".format(self.client_id, self.client_secret).encode("ascii")
        basic_auth_encoded = base64.b64encode(basic_auth).decode("utf-8")
        self.headers.update({'Authorization': "Basic {0}".format(basic_auth_encoded)})

    def _query_api(self, path, data=None):
        """Helper method for making a OAuth2-compliant API call.

        Args:
            path: path on the server to call
            data: dictionary of data to send to the server in message body

        Returns:
            the JSON-parsed result body
        """

        return self._request_api(path=path, data=data)

    def login_url(self, scope, state):
        """The URL a user should open in his/her web browser to start the login process.

        When the process is completed, the user is redirected to the URL provided to
        the constructor and passes on an authentication code. This code can be converted into
        an access token for data access.

        Args:
            scope: Scope of data access to ask the user for, e.g. `accounts=ro`
            state: String passed on through the complete login process and to the redirect
                target at the end. It should be used to validate the authenticity of the
                call to the redirect URL

        Returns:
            the URL of the first page of the login process
        """
        return (self.api_endpoint +
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

        Args:
            authentication_code: the code received as part of the call to the redirect
                URL at the end of the logon process

        Returns:
            Dictionary with the following keys:
             - `access_token` - the access token for data access. You can pass it into
             `FigoConnection.open_session` to get a FigoSession and access the user's data
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

    def credential_login(self, username, password, scope=None):
        """
        Return a Token dictionary which tokens are used for further API actions.

        Args:
            username (str): Figo username
            password (str): Figo password
            scope (str): Space delimited set of requested permissions.
                         Example: "accounts=ro balance=ro transactions=ro offline"

        Returns:
            Dictionary which contains an access token and a refresh token.
        """

        data = {"grant_type": "password",
                "username": username,
                "password": password}
        if scope:
            data["scope"] = scope

        response = self._request_api("/auth/token", data, method="POST")

        if 'error' in response:
            raise FigoException.from_dict(response)

        return {
            'access_token': response['access_token'],
            'refresh_token': response['refresh_token'] if 'refresh_token' in response else None,
            'expires': datetime.now() + timedelta(seconds=response['expires_in']),
            'scope': response['scope'],
        }

    def convert_refresh_token(self, refresh_token):
        """Convert a refresh token (granted for offline access and returned by
        `convert_authentication_code`) into an access token usable for data access.

        Args:
            refresh_token: refresh token returned by `convert_authentication_code`

        Returns:
            Dictionary with the following keys:
             - `access_token` - the access token for data access. You can pass it into
             `FigoConnection.open_session` to get a FigoSession and access the users data
             - `expires` - absolute time the access token expires
        """
        if refresh_token[0] != "R":
            raise Exception("Invalid refresh token")


        data = {
            'refresh_token': refresh_token, 'redirect_uri': self.redirect_uri,
            'grant_type': 'refresh_token'}
        response = self._request_api("/auth/token", data=data, method="POST")

        if 'error' in response:
            raise FigoException.from_dict(response)

        return {'access_token': response['access_token'],
                'expires': datetime.now() + timedelta(seconds=response['expires_in'])}

    def revoke_token(self, token):
        """Revoke a granted access or refresh token and thereby invalidate it.

        Note: this action has immediate effect, i.e. you will not be able use that
        token anymore after this call.

        Args:
            token: access or refresh token to be revoked
        """
        response = self._request_api("/auth/revoke?" + urllib.urlencode({'token': token}))
        if 'error' in response:
            raise FigoException.from_dict(response)

    def add_user(self, name, email, password, language='de'):
        """Create a new figo Account.

        Args:
            name: First and last name
            email: Email address; It must obey the figo username & password policy
            password: New figo Account password; It must obey the figo username & password policy
            language: Two-letter code of preferred language

        Returns:
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

        Args:
            name: First and last name
            email: Email address; It must obey the figo username & password policy
            password: New figo Account password; It must obey the figo username & password policy
            language: Two-letter code of preferred language
            send_newsletter: This flag indicates whether the user has agreed to be contacted by
                email

        Returns:
            Token dictionary for further API access
        """
        self.add_user(name, email, password, language)
        return self.credential_login(email, password)


class FigoSession(FigoObject):
    """
    Represents a user-bound connection to the figo connect API and allows access to the users data.
    """
    def __init__(self, access_token, sync_poll_retry=20,
                 api_endpoint=CREDENTIALS['api_endpoint'],
                 fingerprints=CREDENTIALS['ssl_fingerprints'],
                 language=None,
                 ):
        """Create a FigoSession instance.

        Args:
            access_token (str) - the access token to bind this session to a user
            sync_poll_retry (int) - maximum number of synchronization poll retries
            api_endpoint (str) - base URI of the server to call
            fingerprints ([str]) - list of the server's SSL fingerprints
            language (str) - language for HTTP request header
        """
        super(FigoSession, self).__init__(api_endpoint=api_endpoint, fingerprints=fingerprints,
                                          language=language)

        self.access_token = access_token
        self.headers.update({'Authorization': "Bearer {0}".format(self.access_token)})
        self.sync_poll_retry = sync_poll_retry

    @property
    def accounts(self):
        """
        An array of `Account` objects, one for each account the user has granted the app access.
        """
        return self._query_api_object(Account, "/rest/accounts", collection_name="accounts")

    def get_account(self, account_id):
        """Retrieve a specific account.

        Args:
            account_id: id of the account to be retrieved

        Returns:
            Account object for the respective account
        """
        return self._query_api_object(Account, "/rest/accounts/%s" % account_id)

    def add_account(self, country, credentials, bank_code=None, iban=None, save_pin=False):
        """Add a bank account to the figo user.

        Args:
            country (str): country code of the bank to add
            credentials ([str]): list of credentials needed for bank login
            bank_code (str): bank code of the bank to add
            iban (str): iban of the account to add
            save_pin (bool): save credentials on the figo Connect server

        Returns:
            TaskToken: A task token for the account creation task

        Note:
            `bank_code` or `iban` must be set, and `iban` overrides `bank_code`.
        """
        data = {'country': country, 'credentials': credentials, 'save_pin': save_pin}
        if iban:
            data['iban'] = iban
        elif bank_code:
            data['bank_code'] = bank_code

        return self._query_api_object(TaskToken, "/rest/accounts", data, "POST")

    def add_account_and_sync(self, country, credentials, bank_code=None, iban=None, save_pin=False):
        """Add a bank account and start syncing it.

        Args:
            country (str): country code of the bank to add
            credentials ([str]): list of credentials needed for bank login
            bank_code (str): bank code of the bank to add
            iban (str): iban of the account to add
            save_pin (bool): save credentials on the figo Connect server

        Returns:
            TaskToken: A task token for the account creation task

        Note:
            `bank_code` or `iban` must be set, and `iban` overrides `bank_code`.
            The number of sync retries is determined by `FigoSession.sync_poll_retry`.
        """
        task_token = self.add_account(country, credentials, bank_code, iban, save_pin)
        for _ in range(self.sync_poll_retry):
            task_state = self.get_task_state(task_token)
            logger.info("Adding account {0}/{1}: {2}".format(bank_code, iban, task_state.message))
            logger.debug(str(task_state))
            if task_state.is_ended or task_state.is_erroneous:
                break
            sleep(2)
        else:
            raise FigoException(
                "could not sync",
                "task was not finished after {0} tries".format(self.sync_poll_retry)
            )

        if task_state.is_erroneous:
            if task_state.error and task_state.error['code'] == 10000:
                raise FigoPinException(country, credentials, bank_code, iban, save_pin,
                                       error=task_state.error['name'],
                                       error_description=task_state.error['description'],
                                       code=task_state.error['code'])
            raise FigoException("", error_description=task_state.error['message'],
                                code=task_state.error['code'])
        return task_state

    def add_account_and_sync_with_new_pin(self, pin_exception, new_pin):
        """Provide a new pin if the sync task was erroneous because of a wrong pin.

        Args:
            pin_exception: Exception of the sync task for which a new pin will be provided
            new_pin: New pin for the sync task

        Returns:
            The state of the sync task. If the pin was wrong a FigoPinException is thrown
        """
        pin_exception.credentials[1] = new_pin
        return self.add_account_and_sync(
            pin_exception.country,
            pin_exception.credentials,
            pin_exception.bank_code,
            pin_exception.iban,
            pin_exception.save_pin,
        )

    def modify_account(self, account):
        """Modify an account.

        Args:
            account: the modified account to be saved

        Returns:
            Account object for the updated account returned by server
        """
        return self._query_api_object(Account, "/rest/accounts/%s" % account.account_id,
                                      account.dump(), "PUT")

    def remove_account(self, account_or_account_id):
        """Remove an account.

        Args:
            account_or_account_id: account to be removed or its ID
        """
        if isinstance(account_or_account_id, Account):
            account_or_account_id = account_or_account_id.account_id

        query = "/rest/accounts/{0}".format(account_or_account_id)
        self._request_with_exception(query, method="DELETE")

    def sync_account(self, state, redirect_uri=None, account_ids=None, if_not_synced_since=None,
                     sync_tasks=['transactions'], disable_notifications=False, auto_continue=False):
        """
        Args:
            state (str): Arbitrary string to maintain state between this request and the callback,
                e.g. it might contain a session ID from your application.
                The value should also contain a random component, which your
                application checks to prevent cross-site request forgery.
            redirect_uri (str): At the end of the synchronization process a response will be sent to
                this callback URL. The value defaults to the first redirect URI
                configured for the client.
            disable_notifications (bool): This flag indicates whether notifications should be sent
                to your application. Since your application will be notified by
                the callback URL anyway, you might want to disable any
                additional notifications.
            if_not_synced_since (int): If this parameter is set, only those accounts will be
                synchronized, which have not been synchronized within the
                specified number of minutes.
            auto_continue (bool): Automatically acknowledge and ignore any errors.
            account_ids ([str]): Only sync the accounts with these IDs.

        Returns:
            TaskToken: A task token for the synchronization task
        """
        data = {
            'state': state,
            'redirect_uri': redirect_uri,
            'disable_notifications': disable_notifications,
            'if_not_synced_since': if_not_synced_since,
            'auto_continue': auto_continue,
            'account_ids': account_ids,
            'sync_tasks': sync_tasks,
        }

        data = dict((k, v) for k, v in data.items() if v is not None)  # noqa, py26 compatibility
        return self._query_api_object(model=TaskToken, path='/rest/sync', data=data, method='POST')

    def get_account_balance(self, account_or_account_id):
        """Get balance and account limits.

        Args:
            account_or_account_id: account to be queried or its ID

        Returns:
            AccountBalance object for the respective account
        """
        if isinstance(account_or_account_id, Account):
            account_or_account_id = account_or_account_id.account_id

        query = "/rest/accounts/{0}/balance".format(account_or_account_id)
        return self._query_api_object(AccountBalance, query)

    def modify_account_balance(self, account_or_account_id, account_balance):
        """Modify balance or account limits.

        Args:
            account_or_account_id: account to be modified or its ID
            account_balance: modified AccountBalance object to be saved

         Returns:
           AccountBalance object for the updated account as returned by the server
        """
        if isinstance(account_or_account_id, Account):
            account_or_account_id = account_or_account_id.account_id

        query = "/rest/accounts/{0}/balance".format(account_or_account_id)
        return self._query_api_object(AccountBalance, query, account_balance.dump(), "PUT")

    def get_catalog(self):
        """Return a dict with lists of supported banks and payment services.

        Returns:
            dict {'banks': [Service], 'services': [Service]}:
                dict with lists of supported banks and payment services
        """
        catalog = self._request_with_exception("/rest/catalog")
        for k, v in catalog.items():
            catalog[k] = [Service.from_dict(self, service) for service in v]

        return catalog

    def get_supported_payment_services(self, country_code):
        """Return a list of supported credit cards and other payment services.

        Args:
            country_code (str): country code of the requested payment services

        Returns:
            [Service]: list of supported credit cards and other payment services
        """
        services = self._request_with_exception("/rest/catalog/services/%s" % country_code)[
            "services"]
        return [Service.from_dict(self, service) for service in services]

    def get_supported_banks(self, country_code):
        """Return a list of supported banks.

        Args:
            country_code (str): country code of the requested banks

        Retursn:
            [Service]: list of supported banks
        """
        banks = self._request_with_exception("/rest/catalog/banks/%s" % country_code)[
            "banks"]
        return [Service.from_dict(self, bank) for bank in banks]

    def get_login_settings(self, country_code, item_id):
        """Return the login settings of a bank.

        Args:
            country_code (str): country code of the requested bank
            item_id (str): bank code or fake bank code of the requested bank

        Returns:
            LoginSettings: Object that contains information which are needed for
                           logging in to the bank
        """
        return self._query_api_object(LoginSettings,
                                      "/rest/catalog/banks/%s/%s" % (country_code, item_id))

    def get_service_login_settings(self, country_code, item_id):
        """Return the login settings of a payment service.

        Args:
            country_code (str): country code of the requested payment service
            item_id (str): bank code or fake bank code of the requested payment service

        Returns:
            LoginSettings: Object that contains information which are needed for
                           logging in to the payment service.
        """
        return self._query_api_object(LoginSettings,
                                      "/rest/catalog/services/%s/%s" % (country_code, item_id))

    @property
    def notifications(self):
        """An array of `Notification` objects, one for each registered notification."""
        return self._query_api_object(Notification, "/rest/notifications",
                                      collection_name="notifications")

    def get_notification(self, notification_id):
        """Retrieve a specific notification.

        Args:
            notification_id: ID of the notification to be retrieved

        Returns:
            Notification object for the respective notification
        """
        return self._query_api_object(Notification, "/rest/notifications/" + str(notification_id))

    def add_notification(self, notification):
        """Create a new notification.

        Args:
            notification: new notification to be created. It should have no notification_id set

        Returns:
            Notification object for the newly created notification
        """
        return self._query_api_object(Notification, "/rest/notifications", notification.dump(),
                                      "POST")

    def modify_notification(self, notification):
        """Modify a notification.

        Args:
            notification: modified notification object to be saved

        Returns:
            Notification object for the modified notification
        """
        return self._query_api_object(Notification,
                                      "/rest/notifications/" + notification.notification_id,
                                      notification.dump(), "PUT")

    def remove_notification(self, notification_or_notification_id):
        """Remove a notification.

        Args:
            notification_or_notification_id: notification to be removed or its ID
        """
        if isinstance(notification_or_notification_id, Notification):
            notification_or_notification_id = notification_or_notification_id.notification_id

        query = "/rest/notifications/{0}".format(notification_or_notification_id)
        self._request_with_exception(query, method="DELETE")

    @property
    def payments(self):
        """Get an array of `Payment` objects, one for each payment of the user over all accounts.

        Returns:
            List of Payment objects
        """
        return self._query_api_object(Payment, "/rest/payments", collection_name="payments")

    def get_payments(self, account_or_account_id):
        """Get an array of `Payment` objects, one for each payment of the user on
        the specified account.

        Args:
            account_or_account_id: account to be queried or its ID

        Returns:
            List of Payment objects
        """
        if isinstance(account_or_account_id, Account):
            account_or_account_id = account_or_account_id.account_id

        query = "/rest/accounts/{0}/payments".format(account_or_account_id)
        return self._query_api_object(Payment, query, collection_name="payments")

    def get_payment(self, account_or_account_id, payment_id):
        """Get a single `Payment` object.

        Args:
            account_or_account_id: account to be queried or its ID
            payment_id: ID of the payment to be retrieved

        Returns:
            Payment object
        """
        if isinstance(account_or_account_id, Account):
            account_or_account_id = account_or_account_id.account_id

        query = "/rest/accounts/{0}/payments/{1}".format(account_or_account_id, payment_id)
        return self._query_api_object(Payment, query)

    def add_payment(self, payment):
        """Create a new payment.

        Args:
            payment: payment to be created. It should not have its payment_id set.

        Returns:
            Payment object of the newly created payment as returned by the server
        """
        return self._query_api_object(Payment,
                                      "/rest/accounts/{0}/payments".format(payment.account_id),
                                      payment.dump(), "POST")

    def modify_payment(self, payment):
        """Modify a payment.

        Args:
            payment: modified payment object to be modified

        Returns:
            Payment object for the updated payment
        """
        return self._query_api_object(Payment, "/rest/accounts/%s/payments/%s" % (
            payment.account_id, payment.payment_id), payment.dump(), "PUT")

    def remove_payment(self, payment):
        """Remove a payment.

        Args:
            payment:  payment to be removed
        """
        self._request_with_exception(
            "/rest/accounts/%s/payments/%s" % (payment.account_id, payment.payment_id),
            method="DELETE")

    def submit_payment(self, payment, tan_scheme_id, state, redirect_uri=None):
        """Submit payment to bank server.

        Args:
            payment: payment to be submitted
            tan_scheme_id: TAN scheme ID of user-selected TAN scheme
            state: Any kind of string that will be forwarded in the callback response message
            redirect_uri: At the end of the submission process a response will
                be sent to this callback URL

        Returns:
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
            return (self.api_endpoint + "/task/start?id=" +
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
        """Start the given task.

        note:: Deprecated in 3.0.0
          `start_task` will be removed in 3.1.0, it is no longer necessary. Task will start
          immediately on creation if creation is not deferred. For 3.0.0 start_task will call
          task progress once to simulate old behavior for older API versions.

        Args:
            task_token_obj: TaskToken object of the task to start
        """
        self.get_task_state(task_token_obj)

    def get_task_state(self, task_token_obj, pin=None, continue_=None, save_pin=None,
                       response=None):
        """Return the progress of the given task. The kwargs are used to submit additional
        content for the task.

        Args:
            task_token (TaskToken): Token of the task to poll.
            pin (str): Submit PIN. If this parameter is set, then the parameter save_pin must be
                       set, too.
            continue (bool): This flag signals to continue after an error condition or to skip a
                             PIN or challenge-response entry
            save_pin (bool): This flag indicates whether the user has chosen to save the PIN on
                             the figo Connect server
            response (dict): Submit response to challenge.

        Returns:
            TaskState: Object that indicates the current status of the queried task
        """
        logger.debug('Getting task state for: %s', task_token_obj)

        data = {
            "id": task_token_obj.task_token,
            "pin": pin,
            "continue": continue_,
            "save_pin": save_pin,
            "response": response
        }

        data = dict((k, v) for k, v in data.items() if v is not None)  # noqa, py26 compatibility

        return self._query_api_object(TaskState,
                                      "/task/progress?id=%s" % task_token_obj.task_token,
                                      data, "POST")

    def cancel_task(self, task_token_obj):
        """Cancel a task if possible.

        Args:
            task_token_obj: TaskToken object of the task to cancel
        """
        return self._request_with_exception(
            path="/task/cancel?id=%s" % task_token_obj.task_token,
            data={"id": task_token_obj.task_token},
            method="POST")

    @property
    def transactions(self):
        """An array of `Transaction` objects, one for each transaction of the user."""
        return self._query_api_object(Transaction, "/rest/transactions",
                                      collection_name="transactions")

    def get_transactions(self, account_id=None, since=None, count=1000, offset=0,
                         include_pending=False, sort='desc'):
        """Get an array of `Transaction` objects, one for each transaction of the user.

        Args:
            account_id (str): ID of the account for which to list the transactions
            since (str): This parameter can either be a transaction ID or a date.
            count (int): Limit the number of returned transactions.
            offset (int): Which offset into the result set should be used to determine the
                          first transaction to return (useful in combination with count)
            include_pending (bool): This flag indicates whether pending transactions should
                                    be included in the response. Pending transactions are always
                                    included as a complete set, regardless of the `since` parameter.

        Returns:
            [Transaction]: List of `Transaction` objects
        """
        params = {'count': count, 'offset': offset, 'sort': sort,
                  'include_pending': ("1" if include_pending else "0")}
        if since is not None:
            params['since'] = since

        params = urllib.urlencode(params)

        if account_id is not None:
            query = "/rest/accounts/{0}/transactions?{1}".format(account_id, params)
        else:
            query = "/rest/transactions?{0}".format(params)

        return self._query_api_object(Transaction, query, collection_name="transactions")

    def get_transaction(self, account_or_account_id, transaction_id):
        """Retrieve a specific transaction.

        Args:
            account_or_account_id: account to be queried or its ID
            transaction_id: ID of the transaction to be retrieved

        Returns:
            a Transaction object representing the transaction to be retrieved
        """
        if isinstance(account_or_account_id, Account):
            account_or_account_id = account_or_account_id.account_id

        query = "/rest/accounts/{0}/transactions/{1}".format(account_or_account_id, transaction_id)
        return self._query_api_object(Transaction, query)

    @property
    def securities(self):
        """An array of `Security` objects, one for each transaction of the user."""
        return self._query_api_object(Security, "/rest/securities", collection_name="securities")

    def get_securities(self, account_id=None, since=None, count=1000, offset=0, accounts=None):
        """Get an array of `Security` objects, one for each security of the user.

        Args:
            account_id: ID of the account for which to list the securities
            since: this parameter can either be a transaction ID or a date
            count: limit the number of returned transactions
            offset: which offset into the result set should be used to determine the first
                transaction to return (useful in combination with count)
            accounts: if retrieving the securities for all accounts, filter the
                securities to be only from these accounts

        Returns:
            List of Security objects
        """
        params = {'count': count, 'offset': offset}
        if accounts is not None and type(accounts) == list:
            params['accounts'] = ",".join(accounts)

        if since is not None:
            params['since'] = since

        params = urllib.urlencode(params)

        if account_id:
            query = "/rest/accounts/{0}/securities?{1}".format(account_id, params)
        else:
            query = "/rest/securities?{0}".format(params)

        return self._query_api_object(Security, query, collection_name="securities")

    def get_security(self, account_or_account_id, security_id):
        """Retrieve a specific security.

        Args:
            account_or_account_id: account to be queried or its ID
            security_id: ID of the security to be retrieved

        Returns:
            a Security object representing the transaction to be retrieved
        """
        if isinstance(account_or_account_id, Account):
            account_or_account_id = account_or_account_id.account_id

        query = "/rest/accounts/{0}/securities/{1}".format(account_or_account_id, security_id)
        return self._query_api_object(Security, query)

    def modify_security(self, account_or_account_id, security_or_security_id, visited=None):
        """Modify a specific security.

        Args:
            account_or_account_id: account to be modified or its ID
            securities_or_security_id: Security or its ID to be modified
            visited: new value of the visited field for the security

        Returns:
            Nothing if the request was successful
        """
        if isinstance(account_or_account_id, Account):
            account_or_account_id = account_or_account_id.account_id
        if isinstance(security_or_security_id, Security):
            security_or_security_id = security_or_security_id.security_id

        query = "/rest/accounts/{0}/securities/{1}".format(account_or_account_id,
                                                           security_or_security_id)
        return self._request_with_exception(query, {"visited": visited}, "PUT")

    def modify_account_securities(self, account_or_account_id, visited=None):
        """
        Modify all securities of an account.

        :Parameters:
         - `account_or_account_id` - account to be modified or its ID
         - `visited` - new value of the visited field for the security

        :Returns:
            Nothing if the request was successful
        """
        if isinstance(account_or_account_id, Account):
            account_or_account_id = account_or_account_id.account_id

        query = "/rest/accounts/{0}/securities".format(account_or_account_id)
        return self._request_with_exception(query, {"visited": visited}, "PUT")

    def modify_user_securities(self, visited=None):
        """Modify all securities from the current user.

        Args:
            visited: new value of the visited field for the security

        Returns:
            Nothing if the request was successful
        """
        return self._request_with_exception("/rest/securities", {"visited": visited}, "PUT")

    def modify_account_transactions(self, account_or_account_id, visited=None):
        """Modify all transactions of a specific account.

        Args:
            account_or_account_id: account to be modified or its ID
            visited: new value of the visited field for the transactions

        Returns:
            Nothing if the request was successful
        """
        if isinstance(account_or_account_id, Account):
            account_or_account_id = account_or_account_id.account_id

        query = "/rest/accounts/{0}/transactions".format(account_or_account_id)
        return self._request_with_exception(query, {"visited": visited}, "PUT")

    def modify_user_transactions(self, visited=None):
        """Modify all transactions of the current user.

        Args:
            visited: new value of the visited field for the transactions

        Returns:
            Nothing if the request was successful
        """
        return self._request_with_exception("/rest/transactions", {"visited": visited}, "PUT")

    def delete_transaction(self, account_or_account_id, transaction_or_transaction_id):
        """Delete a specific transaction.

        Args:
            account_or_account_id: account to be modified or its ID
            transaction_or_transaction_id: Transaction or its ID to be deleted

        Returns:
            Nothing if the request was successful
        """
        if isinstance(account_or_account_id, Account):
            account_or_account_id = account_or_account_id.account_id
        if isinstance(transaction_or_transaction_id, Transaction):
            transaction_or_transaction_id = transaction_or_transaction_id.transaction_id

        query = "/rest/accounts/{0}/transactions/{1}".format(account_or_account_id,
                                                             transaction_or_transaction_id)
        return self._request_with_exception(query, method="DELETE")

    def get_bank(self, bank_id):
        """Get bank.

        Args:
            bank_id: ID of the bank to be retrieved.

        Returns:
            a `BankContact` object representing the bank to be retrieved
        """
        return self._query_api_object(BankContact, "/rest/banks/%s" % bank_id)

    def modify_bank(self, bank):
        """Modify a bank.

        Args:
            bank: modified bank object to be saved

        Returns:
            BankContact object for the updated bank
        """
        return self._query_api_object(BankContact, "/rest/banks/{0}".format(bank.bank_id),
                                      bank.dump(),
                                      "PUT")

    def remove_bank_pin(self, bank_or_bank_id):
        """Remove the stored PIN for a bank (if there was one).

        Returns:
            bank_or_bank_id: bank whose pin should be removed or its ID
        """
        if isinstance(bank_or_bank_id, BankContact):
            bank_or_bank_id = bank_or_bank_id.bank_id

        query = "/rest/banks/{0}/remove_pin".format(bank_or_bank_id)
        self._request_with_exception(query, method="POST")

    @property
    def user(self):
        """Get the current figo Account.

        Returns:
            User object for the current figo Account
        """
        return self._query_api_object(User, "/rest/user")

    def modify_user(self, user):
        """Modify figo Account.

        Args:
            user: modified user object to be saved

        Return:
            User object for the updated figo Account
        """
        return self._query_api_object(User, "/rest/user", user.dump(), "PUT")

    def remove_user(self):
        """Delete figo Account."""
        self._request_with_exception("/rest/user", method="DELETE")

    def get_sync_url(self, state, redirect_uri):
        """URL to trigger a synchronization.

        The user should open this URL in a web browser to synchronize his/her accounts with
        the respective bank servers. When the process is finished, the user is
        redirected to the provided URL.

        Args:
            state: String passed on through the complete synchronization process and to
                the redirect target at the end. It should be used to validate the authenticity
                of the call to the redirect URL
            redirect_uri: URI the user is redirected to after the process completes

        Returns:
            the URL to be opened by the user.
        """
        response = self._request_with_exception("/rest/sync",
                                                {"state": state, "redirect_uri": redirect_uri},
                                                method="POST")
        if response is None:
            return None
        else:
            return (self.api_endpoint + "/task/start?id=" +
                    response['task_token'])

    def parse_webhook_notification(self, message_body):
        """Parse a webhook notification and get a WebhookNotification object.

        Args:
            message_body: message body of the webhook message (as string or dict)

        Returns:
            a WebhookNotification object
        """
        if not isinstance(message_body, dict):
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
