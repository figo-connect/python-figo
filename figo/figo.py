import base64
import json
import logging
import os
import re
from datetime import datetime, timedelta
from urllib.parse import urlencode

from dotenv import load_dotenv
from requests import Session

# TODO: FigoPinException is used by figo_connection/utils.py (ownly-backend)
#   we need to verify if it is required
from .exceptions import (  # noqa: F401
    ERROR_MESSAGES,
    FigoException,
    FigoPinException,
)
from .models import (
    Account,
    AccountBalance,
    BankContact,
    Challenge,
    LoginSettings,
    Notification,
    Payment,
    PaymentProposal,
    Security,
    Service,
    StandingOrder,
    Sync,
    TaskState,
    Transaction,
    User,
    WebhookNotification,
)
from .utils import filter_keys, filter_none, get_account_id
from .version import __version__

load_dotenv()
logger = logging.getLogger(__name__)

API_ENDPOINT = os.getenv("FIGO_API_ENDPOINT")


class FigoObject:
    """A FigoObject has the ability to communicate with the Figo API."""

    def __init__(self, api_endpoint=API_ENDPOINT, language=None):
        """Create a FigoObject instance.

        Args:
            api_endpoint (str): base URI of the server to call
            language (str): language for HTTP request header
        """
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "python_figo/{0}".format(__version__),
        }
        self.language = language
        self.api_endpoint = api_endpoint

    def _request_api(
        self, path, data=None, method="GET", raise_exception=False
    ):
        """Helper method for making a REST-compliant API call.

        Args:
            path: path on the server to call
            data: dictionary of data to send to the server in message body
            method: HTTP verb to use for the request
            raise_exception: flag to trigger raise Exception when status not
                in range 200 - 299 and JSON data has error exception

        Returns:
            the JSON-parsed result body
        """
        complete_path = self.api_endpoint + path

        session = Session()
        session.headers.update(self.headers)

        try:
            response = session.request(method, complete_path, json=data)
        except Exception as err:
            logger.error("Request Error was raised: {}".format(err))
        else:
            logger.debug(
                "{} '{}' result with status {} and text: {}".format(
                    method,
                    complete_path,
                    response.status_code,
                    response.text[:2000],
                )
            )
        finally:
            session.close()

        if response.text == "":
            data = {}
        else:
            try:
                data = response.json()
            except Exception as err:
                logger.error(
                    "Convert data to JSON format failed: {}".format(err)
                )
                data = {}

        if 200 <= response.status_code < 300:
            return data
        elif self._has_error(data):
            if raise_exception:
                raise FigoException.from_dict(data)
            return data
        elif response.status_code in ERROR_MESSAGES:
            return {"error": ERROR_MESSAGES[response.status_code]}

        logger.warning(
            "Querying the API failed when accessing '%s': %d",
            complete_path,
            response.status_code,
        )

        return {
            "error": {
                "message": "internal_server_error",
                "description": "We are very sorry, but something went wrong",
                "code": 90000,
            }
        }

    def _request_with_exception(self, path, data=None, method="GET"):
        """Helper to trigger raise exception on _request_api"""
        return self._request_api(path, data, method, raise_exception=True)

    @staticmethod
    def _has_error(response):
        return "error" in response and response["error"]

    def _query_api_object(
        self, model, path, data=None, method="GET", collection_name=None
    ):
        """Helper method using _request_with_exception but encapsulating the
        result as an object.
        """
        response = self._request_with_exception(path, data, method)
        if response is None:
            return None
        elif collection_name is None:
            return model.from_dict(self, response)
        elif collection_name == "collection":
            # Some collections in the API response ARE NOT embedded in
            # collection name. (Ex: challenges, accesses)
            return [
                model.from_dict(self, dict_entry) for dict_entry in response
            ]
        else:
            return [
                model.from_dict(self, dict_entry)
                for dict_entry in response[collection_name]
            ]

    @property
    def language(self):
        return self.headers.get("Accept-Language")

    @language.setter
    def language(self, lang):
        if lang:
            self.headers["Accept-Language"] = lang
        elif self.headers.get("Accept-Language"):
            del self.headers["Accept-Language"]


class FigoConnection(FigoObject):
    """Representing a not user-bound connection to the figo connect API.

    Its main purpose is to let user login via the OAuth2 API.
    """

    def __init__(
        self,
        client_id,
        client_secret,
        redirect_uri,
        api_endpoint=API_ENDPOINT,
        language=None,
    ):
        """Create a FigoConnection instance.

        Args:
            client_id (str): the OAuth Client ID as provided by your figo
                developer contact
            client_secret (str): the OAuth Client Secret as provided by your
                figo developer contact
            redirect_uri (str): the URI the users gets redirected to after the
                login is finished or if they press `cancel`
            api_endpoint (str): base URI of the server to call
            language (str): language for HTTP request header
        """
        super().__init__(api_endpoint, language)

        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        basic_auth = "{0}:{1}".format(
            self.client_id, self.client_secret
        ).encode("ascii")
        basic_auth_encoded = base64.b64encode(basic_auth).decode("utf-8")
        self.headers.update(
            {"Authorization": "Basic {0}".format(basic_auth_encoded)}
        )

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
        """The URL a user should open in his/her web browser to start the
        login process.

        When the process is completed, the user is redirected to the URL
        provided to the constructor and passes on an authentication code. This
        code can be converted into an access token for data access.

        Args:
            scope: Scope of data access to ask the user for, e.g. `accounts=ro`
            state: String passed on through the complete login process and to
                the redirect target at the end. It should be used to validate
                the authenticity of the call to the redirect URL

        Returns:
            the URL of the first page of the login process
        """
        return (
            self.api_endpoint
            + "/auth/code?"
            + urlencode(
                {
                    "response_type": "code",
                    "client_id": self.client_id,
                    "redirect_uri": self.redirect_uri,
                    "scope": scope,
                    "state": state,
                }
            )
        )

    def convert_authentication_code(self, authentication_code):
        """Convert the authentication code received as result of the login
        process into an access token usable for data access.

        Args:
            authentication_code: the code received as part of the call to the
                redirect URL at the end of the logon process

        Returns:
            Dictionary with the following keys:
                - `access_token` - the access token for data access. You can
                    pass it into `FigoConnection.open_session` to get
                    a FigoSession and access the user's data
                - `refresh_token` - if the scope contained the `offline` flag,
                    also a refresh token is generated. It can be used to
                    generate new access tokens, when the first one has expired.
                - `expires` - absolute time the access token expires
        """
        if authentication_code[0] != "O":
            raise Exception("Invalid authentication code")

        response = self._request_api(
            "/auth/token",
            data={
                "code": authentication_code,
                "redirect_uri": self.redirect_uri,
                "grant_type": "authorization_code",
            },
            method="POST",
        )

        if "error" in response:
            raise FigoException.from_dict(response)

        return {
            "access_token": response["access_token"],
            "refresh_token": response["refresh_token"]
            if "refresh_token" in response
            else None,
            "expires": datetime.now()
            + timedelta(seconds=response["expires_in"]),
        }

    def credential_login(self, username, password, scope=None):
        """Return a Token dictionary which tokens are used for further API
        actions.

        Args:
            username (str): Figo username
            password (str): Figo password
            scope (str): Space delimited set of requested permissions.
                 Example: "accounts=ro balance=ro transactions=ro offline"

        Returns:
            Dictionary which contains an access token and a refresh token.
        """

        data = filter_none(
            {
                "grant_type": "password",
                "username": username,
                "password": password,
                "scope": scope,
            }
        )

        response = self._request_api("/auth/token", data, method="POST")

        if "error" in response:
            raise FigoException.from_dict(response)

        return {
            "access_token": response["access_token"],
            "refresh_token": response["refresh_token"]
            if "refresh_token" in response
            else None,
            "expires": datetime.now()
            + timedelta(seconds=response["expires_in"]),
            "scope": response["scope"],
        }

    def convert_refresh_token(self, refresh_token):
        """Convert a refresh token (granted for offline access and returned by
        `convert_authentication_code`) into an access token usable for data
        access.

        Args:
            refresh_token: refresh token returned by
                `convert_authentication_code`

        Returns:
            Dictionary with the following keys:
                - `access_token` - the access token for data access. You can
                    pass it into `FigoConnection.open_session` to get
                    a FigoSession and access the users data
                - `expires` - absolute time the access token expires
        """
        if refresh_token[0] != "R":
            raise Exception("Invalid refresh token")

        data = {
            "refresh_token": refresh_token,
            "redirect_uri": self.redirect_uri,
            "grant_type": "refresh_token",
        }
        response = self._request_api("/auth/token", data=data, method="POST")

        if "error" in response:
            raise FigoException.from_dict(response)

        return {
            "access_token": response["access_token"],
            "expires": datetime.now()
            + timedelta(seconds=response["expires_in"]),
        }

    def revoke_token(self, token):
        """Revoke a granted access or refresh token and thereby invalidate it.

        Note: this action has immediate effect, i.e. you will not be able use
            that token anymore after this call.

        Args:
            token: access or refresh token to be revoked
        """
        response = self._request_api(
            "/auth/revoke?" + urlencode({"token": token})
        )
        if "error" in response:
            raise FigoException.from_dict(response)

    def add_user(self, name, email, password, language="de"):
        """Create a new figo Account.

        Args:
            name: First and last name
            email: Email address; It must obey the figo username & password
                policy
            password: New figo Account password; It must obey the figo
                username & password policy
            language: Two-letter code of preferred language

        Returns:
            Auto-generated recovery password.
        """
        response = self._request_api(
            path="/auth/user",
            data={
                "full_name": name,
                "email": email,
                "password": password,
                "language": language,
            },
            method="POST",
        )

        if response is None:
            return None
        elif "error" in response:
            raise FigoException.from_dict(response)
        else:
            return response

    def add_user_and_login(self, name, email, password, language="de"):
        """Create a new figo account and get a session token for the new
        account.

        Args:
            name: First and last name
            email: Email address; It must obey the figo username & password
                policy
            password: New figo Account password; It must obey the figo
                username & password policy
            language: Two-letter code of preferred language

        Returns:
            Token dictionary for further API access
        """
        self.add_user(name, email, password, language)
        return self.credential_login(email, password)

    def get_version(self):
        """
        Returns the version of the API.
        """
        return self._request_api(path="/version", method="GET")

    def get_catalog(self, q=None, country_code=None):
        """Return a dict with lists of supported banks and payment services,
        with client auth.

        Returns:
            dict {"banks": [BankContact], "services": [Service]}:
                dict with lists of supported banks and payment services
        """
        options = filter_none({"country": country_code, "q": q})
        catalog = self._query_api("/catalog?" + urlencode(options))

        for k, v in catalog.items():
            if k == "banks":
                catalog[k] = [BankContact.from_dict(self, bank) for bank in v]
            elif k == "services":
                catalog[k] = [
                    Service.from_dict(self, service) for service in v
                ]

        return catalog


class FigoSession(FigoObject):
    """Represents a user-bound connection to the figo connect API and allows
    access to the users data.
    """

    def __init__(
        self,
        access_token,
        sync_poll_retry=20,
        api_endpoint=API_ENDPOINT,
        language=None,
    ):
        """Create a FigoSession instance.

        Args:
            access_token (str): the access token to bind this session to
                a user
            sync_poll_retry (int): maximum number of synchronization poll
                retries
            api_endpoint (str): base URI of the server to call
            language (str): language for HTTP request header
        """
        super().__init__(api_endpoint, language)

        self.access_token = access_token
        self.headers.update(
            {"Authorization": "Bearer {0}".format(self.access_token)}
        )
        self.sync_poll_retry = sync_poll_retry

    @property
    def accounts(self):
        """An array of `Account` objects, one for each account the user has
        granted the app access.
        """
        return self._query_api_object(
            Account, "/rest/accounts", collection_name="accounts"
        )

    def get_account(self, account_or_account_id):
        """Get bank account data.

        Args:
            account_or_account_id: account to be queried or its ID

        Returns:
            Account: An account accessible from Token
        """
        return self._query_api_object(
            Account,
            path="/rest/accounts/{0}".format(
                get_account_id(account_or_account_id)
            ),
            method="GET",
        )

    def get_accounts(self):
        """Get list of bank accounts.

        Returns:
            List of Accounts accessible from Token
        """
        return self._query_api_object(
            Account,
            path="/rest/accounts",
            method="GET",
            collection_name="accounts",
        )

    def modify_account(self, account):
        """Modify an account.

        Args:
            account: the modified account to be saved

        Returns:
            Account object for the updated account returned by server
        """
        return self._query_api_object(
            Account,
            "/rest/accounts/%s" % account.account_id,
            account.dump(),
            "PUT",
        )

    def remove_account(self, account_or_account_id):
        """Remove an account.

        Args:
            account_or_account_id: account to be removed or its ID
        """
        account_id = get_account_id(account_or_account_id)
        path = f"/rest/accounts/{account_id}"
        return self._request_with_exception(path, method="DELETE")

    def add_sync(
        self,
        access_id,
        disable_notifications,
        redirect_uri,
        state,
        credentials,
        save_secrets,
    ):
        """Start synchronization process.

        Args:
            access_id (str): figo ID of the provider access, Required
            disable_notifications (bool): This flag indicates whether
                notifications should be sent to your application, Optional,
                default: False
            redirect_uri (str): The URI to which the end user is redirected in
                OAuth cases, Optional
            state (str): Arbitrary string to maintain state between this
                request and the callback
            credentials (obj): Credentials used for authentication with the
                financial service provider.
            save_secrets (bool): Indicates whether the confidential parts of
                the credentials should be saved, default: False

        Returns:
          Object: synchronization operation.
        """
        data = filter_none(
            {
                "disable_notifications": disable_notifications,
                "redirect_uri": redirect_uri,
                "state": state,
                "credentials": credentials,
                "save_secrets": save_secrets,
            }
        )

        return self._query_api_object(
            Sync,
            "/rest/accesses/{0}/syncs".format(access_id),
            data=data,
            method="POST",
        )

    def get_synchronization_status(self, access_id, sync_id):
        """Get synchronization status.

        Args:
            access_id (str): figo ID of the provider access, Required
            sync_id (str): figo ID of the synchronization operation, Required

        Returns:
            Object: synchronization operation.
        """
        return self._query_api_object(
            Sync,
            "/rest/accesses/{0}/syncs/{1}".format(access_id, sync_id),
            method="GET",
        )

    def get_synchronization_challenges(self, access_id, sync_id):
        """Get synchronization challenges.

        Args:
            access_id (str): figo ID of the provider access, Required
            sync_id (str): figo ID of the synchronization operation, Required

        Returns:
            Object: List of challenges associated with synchronization
                operation.
        """
        return self._query_api_object(
            Challenge,
            "/rest/accesses/{0}/syncs/{1}/challenges".format(
                access_id, sync_id
            ),
            method="GET",
            collection_name="collection",
        )

    def get_synchronization_challenge(self, access_id, sync_id, challenge_id):
        """Get synchronization challenge.

        Args:
            access_id (str): figo ID of the provider access, Required
            sync_id (str): figo ID of the synchronization operation, Required
            challenge_id (str): figo ID of the challenge, Required

        Returns:
            Object: Challenge associated with synchronization operation.
        """
        return self._query_api_object(
            Challenge,
            "/rest/accesses/{0}/syncs/{1}/challenges/{2}".format(
                access_id, sync_id, challenge_id
            ),
            method="GET",
        )

    def solve_synchronization_challenge(
        self, access_id, sync_id, challenge_id, data
    ):
        """Solve synchronization challenge.

        Args:
            access_id (str): figo ID of the provider access, Required
            sync_id (str): figo ID of the synchronization operation, Required
            challenge_id (str): figo ID of the challenge, Required

        Returns:
            Successful response or error dict.
        """
        return self._request_api(
            path="/rest/accesses/{0}/syncs/{1}/challenges/{2}/response".format(
                access_id, sync_id, challenge_id
            ),
            data=data,
            method="POST",
        )

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
            AccountBalance object for the updated account as returned by the
                server
        """
        if isinstance(account_or_account_id, Account):
            account_or_account_id = account_or_account_id.account_id

        query = "/rest/accounts/{0}/balance".format(account_or_account_id)
        return self._query_api_object(
            AccountBalance, query, account_balance.dump(), "PUT"
        )

    def get_catalog(self, country_code=None):
        """Return a dict with lists of supported banks and payment services.

        Returns:
            dict {"banks": [Service], "services": [Service]}:
                dict with lists of supported banks and payment services
        """
        options = filter_none({"country": country_code})

        catalog = self._request_with_exception(
            "/rest/catalog?" + urlencode(options)
        )
        for k, v in catalog.items():
            catalog[k] = [Service.from_dict(self, service) for service in v]

        return catalog

    def add_access(self, access_method_id, credentials, consent):
        """Add provider access

        Args:
            access_method_id (str): figo ID of the provider access method.
                [required]
            credentials (Crendentials object): Credentials used for
                authentication with the financial service provider.
            consent (Consent object): Configuration of the PSD2 consents.
                Is ignored for non-PSD2 accesses.

        Returns:
            Access object added
        """
        data = filter_none(
            {
                "access_method_id": access_method_id,
                "credentials": credentials,
                "consent": consent,
            }
        )
        return self._request_api(
            path="/rest/accesses", data=data, method="POST"
        )

    def get_accesses(self):
        """List all connected provider accesses of user.

        Returns:
            Array of Access objects
        """
        return self._request_with_exception("/rest/accesses")

    def get_access(self, access_id):
        """Retrieve the details of a specific provider access identified by
        its ID.

        Args:
            access_id (str): figo ID of the provider access. [required]

        Returns:
            Access object matching the access_id
        """
        return self._request_with_exception(
            "/rest/accesses/{0}".format(access_id), method="GET"
        )

    def remove_pin(self, access_id):
        """Remove a PIN from the API backend that has been previously stored
        for automatic synchronization or ease of use.

        Args:
            access_id (str): figo ID of the provider access. [required]

        Returns:
            Access object for which the PIN was removed
        """
        return self._request_api(
            path="/rest/accesses/%s/remove_pin" % access_id, method="POST"
        )

    def get_supported_payment_services(self, country_code):
        """Return a list of supported credit cards and other payment services.

        Args:
            country_code (str): country code of the requested payment services

        Returns:
            [Service]: list of supported credit cards and other payment
                services
        """
        services = self._request_with_exception(
            "/rest/catalog/services/%s" % country_code
        )["services"]
        return [Service.from_dict(self, service) for service in services]

    def get_supported_banks(self, country_code):
        """Return a list of supported banks.

        Args:
            country_code (str): country code of the requested banks

        Returns:
            [Service]: list of supported banks
        """
        banks = self._request_with_exception(
            "/rest/catalog/banks/%s" % country_code
        )["banks"]
        return [Service.from_dict(self, bank) for bank in banks]

    def get_login_settings(self, country_code, item_id):
        """Return the login settings of a bank.

        Args:
            country_code (str): country code of the requested bank
            item_id (str): bank code or fake bank code of the requested bank

        Returns:
            LoginSettings: Object that contains information which are needed
                for logging in to the bank
        """
        query_params = urlencode({"country": country_code, "q": item_id})

        # now the catalog returns matches for all possible banks
        response = self._query_api_object(
            LoginSettings,
            "/catalog/banks?{}".format(query_params),
            collection_name="collection",
        )
        if len(response) > 0:
            return response[0]

        err_msg = "Login settings for bank {} were not found".format(item_id)

        raise FigoException(
            error="login_settings_not_found", error_description=err_msg
        )

    def get_service_login_settings(self, country_code, item_id):
        """Return the login settings of a payment service.

        Args:
            country_code (str): country code of the requested payment service
            item_id (str): bank code or fake bank code of the requested
                payment service

        Returns:
            LoginSettings: Object that contains information which are needed
                for logging in to the payment service.
        """
        return self._query_api_object(
            LoginSettings,
            "/rest/catalog/services/%s/%s" % (country_code, item_id),
        )

    def get_standing_orders(
        self,
        account_or_account_id=None,
        accounts=None,
        count=None,
        offset=None,
        cents=None,
    ):
        """Get an array of `StandingOrder` objects, one for each standing
        order of the user on the specified account.

        Args:
            account_or_account_id: account to be queried or its ID, Optional
            accounts: Comma separated list of account IDs, Optional
            count: Limit the number of returned items, Optional
            offset: Skip this number of transactions in the response, Optional
            cents: If true amounts will be shown in cents, Optional, default:
                False

        Returns:
            List of standing order objects
        """

        options = filter_none(
            {
                "accounts": accounts,
                "count": count,
                "offset": offset,
                "cents": cents,
            }
        )

        account_id = get_account_id(account_or_account_id)
        if account_id:
            query = "/rest/accounts/{0}/standing_orders?{1}".format(
                account_id, urlencode(options)
            )
        else:
            query = "/rest/standing_orders?{0}".format(urlencode(options))

        return self._query_api_object(
            StandingOrder, query, collection_name="standing_orders"
        )

    @property
    def notifications(self):
        """An array of `Notification` objects, one for each registered
        notification.
        """
        return self._query_api_object(
            Notification,
            "/rest/notifications",
            collection_name="notifications",
        )

    def get_notification(self, notification_id):
        """Retrieve a specific notification.

        Args:
            notification_id: ID of the notification to be retrieved

        Returns:
            Notification object for the respective notification
        """
        return self._query_api_object(
            Notification, "/rest/notifications/" + str(notification_id)
        )

    def add_notification(self, notification):
        """Create a new notification.

        Args:
            notification: new notification to be created. It should have no
                notification_id set

        Returns:
            Notification object for the newly created notification
        """
        return self._query_api_object(
            Notification, "/rest/notifications", notification.dump(), "POST"
        )

    def modify_notification(self, notification):
        """Modify a notification.

        Args:
            notification: modified notification object to be saved

        Returns:
            Notification object for the modified notification
        """
        return self._query_api_object(
            Notification,
            "/rest/notifications/" + notification.notification_id,
            notification.dump(),
            "PUT",
        )

    def remove_notification(self, notification_or_notification_id):
        """Remove a notification.

        Args:
            notification_or_notification_id: notification to be removed or its
                ID
        """
        if isinstance(notification_or_notification_id, Notification):
            notification_or_notification_id = (
                notification_or_notification_id.notification_id
            )

        query = "/rest/notifications/{0}".format(
            notification_or_notification_id
        )
        self._request_with_exception(query, method="DELETE")

    @property
    def payments(self):
        """Get an array of `Payment` objects, one for each payment of the user
        over all accounts.

        Returns:
            List of Payment objects
        """
        return self._query_api_object(
            Payment, "/rest/payments", collection_name="payments"
        )

    def get_payments(
        self, account_or_account_id, accounts, count, offset, cents
    ):
        """Get an array of `Payment` objects, one for each payment of the user
        on the specified account.

        Args:
            account_or_account_id: account to be queried or its ID
            accounts: Comma separated list of account IDs.
            count: Limit the number of returned items, Optional
            offset: Skip this number of transactions in the response, Optional
            cents: If true amounts will be shown in cents, Optional, default:
                False

        Returns:
            List of Payment objects
        """

        options = filter_none(
            {
                "accounts": accounts,
                "count": count,
                "offset": offset,
                "cents": cents,
            }
        )

        account_id = get_account_id(account_or_account_id)
        if account_id:
            query = "/rest/accounts/{0}/payments?{1}".format(
                account_id, urlencode(options)
            )
        else:
            query = "/rest/payments?{0}".format(urlencode(options))

        return self._query_api_object(
            Payment, query, collection_name="payments"
        )

    def get_payment(self, account_or_account_id, payment_id, cents):
        """Get a single `Payment` object.

        Args:
            account_or_account_id: account to be queried or its ID
            payment_id: ID of the payment to be retrieved
            cents (bool): If true amounts will be shown in cents, Optional,
                default: False

        Returns:
            Payment object
        """
        options = {"cents": cents} if cents else {}

        query = "/rest/accounts/{0}/payments/{1}?{2}".format(
            get_account_id(account_or_account_id),
            payment_id,
            urlencode(options),
        )
        return self._query_api_object(Payment, query)

    def add_payment(self, payment):
        """Create a new payment.

        Args:
            payment: payment to be created. It should not have its payment_id
                set.

        Returns:
            Payment object of the newly created payment as returned by the
                server
        """
        return self._query_api_object(
            Payment,
            "/rest/accounts/{0}/payments".format(payment.account_id),
            payment.dump(),
            "POST",
        )

    def modify_payment(self, payment):
        """Modify a payment.

        Args:
            payment: modified payment object to be modified

        Returns:
            Payment object for the updated payment
        """
        return self._query_api_object(
            Payment,
            "/rest/accounts/%s/payments/%s"
            % (payment.account_id, payment.payment_id),
            payment.dump(),
            "PUT",
        )

    def remove_payment(self, payment):
        """Remove a payment.

        Args:
            payment: payment to be removed
        """
        self._request_with_exception(
            "/rest/accounts/%s/payments/%s"
            % (payment.account_id, payment.payment_id),
            method="DELETE",
        )

    def submit_payment(self, payment, tan_scheme_id, state, redirect_uri=None):
        """Submit payment to bank server.

        Args:
            payment: payment to be submitted, Required
            tan_scheme_id: TAN scheme ID of user-selected TAN scheme, Required
            state: Any kind of string that will be forwarded in the callback
                response message, Required
            redirect_uri: At the end of the submission process a response will
                be sent to this callback URL, Optional

        Returns:
            the URL to be opened by the user for the TAN process
        """
        params = {"tan_scheme_id": tan_scheme_id, "state": state}
        if redirect_uri is not None:
            params["redirect_uri"] = redirect_uri

        response = self._request_with_exception(
            "/rest/accounts/%s/payments/%s/init"
            % (payment.account_id, payment.payment_id),
            params,
            "POST",
        )
        return response

    def get_payment_status(self, payment, init_id):
        """Get initiation status for  payment initiated to bank server.

        Args:
            payment: payment to be retrieved the status for, Required
            init_id: initiation id, Required

        Returns:
            the initiation status of the payment
        """
        response = self._request_with_exception(
            "/rest/accounts/%s/payments/%s/init/%s"
            % (payment.account_id, payment.payment_id, init_id),
            None,
            "GET",
        )
        return response

    def get_payment_challenges(
        self, account_or_account_id, payment_id, init_id
    ):
        """List payment challenges

        Args:
            account_or_account_id: account to be queried or its ID, Required
            payment: payment to be retrieved the status for, Required
            init_id: initiation id, Required

        Returns:
            List of challenges for the required payment
        """
        account_id = get_account_id(account_or_account_id)

        return self._query_api_object(
            Challenge,
            "/rest/accounts/{0}/payments/{1}/init/{2}/challenges".format(
                account_id, payment_id, init_id
            ),
            "GET",
        )

    def get_payment_challenge(
        self, account_or_account_id, payment_id, init_id, challenge_id
    ):
        """Get payment challenge

        Args:
            account_or_account_id: account to be queried or its ID, Required
            payment: payment to be retrieved the status for, Required
            init_id: initiation id, Required
            challenge_id: challenge id, Required

        Returns:
            Challenge: The required challenge for the payment
        """
        account_id = get_account_id(account_or_account_id)

        return self._query_api_object(
            Challenge,
            "/rest/accounts/{0}/payments/{1}/init/{2}/challenges/{3}".format(
                account_id, payment_id, init_id, challenge_id
            ),
            "GET",
        )

    def solve_payment_challenges(
        self, account_or_account_id, payment_id, init_id, challenge_id, payload
    ):
        """Get payment challenge

        Args:
            account_or_account_id (str): account to be queried or its ID,
                Required
            payment_id (str): payment to be retrieved the status for, Required
            init_id (str): initiation id, Required
            challenge_id (str): challenge id, Required
            payload (one of):
                AuthMethodSelectResponse:
                    - method_id (str): figo ID of TAN scheme.
                ChallengeResponse:
                    - value (str): Response to the auth challenge. The source
                        of the value depends on the selected authentication
                        method.
                ChallengeResponseJWE:
                    - type (str): The type of the value. Always set to the
                        value "encrypted".
                    - value (str): JWE encrypted auth challenge response.

        Returns:
            Challenge: The required challenge for the payment
        """
        account_id = get_account_id(account_or_account_id)
        path = (
            f"/rest/accounts/{account_id}/payments/{payment_id}/init/{init_id}"
            f"/challenges/{challenge_id}/response"
        )
        return self._query_api_object(Challenge, path, payload, "POST",)

    def get_standing_order(
        self,
        standing_order_id,
        account_or_account_id=None,
        accounts=None,
        cents=None,
    ):
        """Get a single `StandingOrder` object.

        Args:
            standing_order_id: ID of the standing order to be retrieved,
                Required
            account_or_account_id: account to be queried or its ID, Optional
            cents (bool): If true amounts will be shown in cents, Optional,
                default: False

        Returns:
            standing order object
        """
        options = filter_none({"accounts": accounts, "cents": cents})

        account_id = get_account_id(account_or_account_id)
        if account_id:
            query = "/rest/accounts/{0}/standing_orders/{1}?{2}".format(
                account_id, standing_order_id, urlencode(options)
            )
        else:
            query = "/rest/standing_orders/{0}?{1}".format(
                standing_order_id, urlencode(options)
            )

        return self._query_api_object(StandingOrder, query)

    def remove_standing_order(
        self, standing_order_id, account_or_account_id=None
    ):
        """Remove a standing order.

        Args:
            standing_order_id: standing order to be removed, Required
            account_or_account_id: account to be queried or its ID, Optional
        """
        account_id = get_account_id(account_or_account_id)
        if account_id:
            path = "/rest/accounts/{0}/standing_orders/{1}".format(
                account_id, standing_order_id
            )
        else:
            path = "/rest/standing_orders/{0}".format(standing_order_id)

        self._request_with_exception(path, method="DELETE")

    @property
    def payment_proposals(self):
        """List of payment proposal object."""
        return self.get_payment_proposals()

    def get_payment_proposals(self):
        """Provide a address book-like list of proposed wire transfer partners.
        """
        response = self._request_with_exception("/rest/address_book")
        return [
            PaymentProposal.from_dict(self, payment_proposal)
            for payment_proposal in response
        ]

    def get_task_state(
        self,
        task_token_obj,
        pin=None,
        continue_=None,
        save_pin=None,
        response=None,
    ):
        """Return the progress of the given task. The kwargs are used to
        submit additional content for the task.

        Args:
            task_token_obj (TaskToken): Token of the task to poll.
            pin (str): Submit PIN. If this parameter is set, then the
                parameter save_pin must be set, too.
            continue_ (bool): This flag signals to continue after an error
                condition or to skip a PIN or challenge-response entry
            save_pin (bool): This flag indicates whether the user has chosen
                to save the PIN on the figo Connect server
            response (dict): Submit response to challenge.

        Returns:
            TaskState: Object that indicates the current status of the queried
                task
        """
        logger.debug("Getting task state for: %s", task_token_obj)

        data = {
            "id": task_token_obj.task_token,
            "pin": pin,
            "continue": continue_,
            "save_pin": save_pin,
            "response": response,
        }

        # TODO: What is this comment?
        data = dict(
            (k, v) for k, v in data.items() if v is not None
        )  # noqa, py26 compatibility

        return self._query_api_object(
            TaskState,
            "/task/progress?id=%s" % task_token_obj.task_token,
            data,
            "POST",
        )

    def cancel_task(self, task_token_obj):
        """Cancel a task if possible.

        Args:
            task_token_obj: TaskToken object of the task to cancel
        """
        return self._request_with_exception(
            path="/task/cancel?id=%s" % task_token_obj.task_token,
            data={"id": task_token_obj.task_token},
            method="POST",
        )

    @property
    def transactions(self):
        """An array of `Transaction` objects, one for each transaction of
        the user.
        """
        return self._query_api_object(
            Transaction, "/rest/transactions", collection_name="transactions"
        )

    def get_transactions(self, account_or_account_id, options):
        """Get an array of Transaction, one for each transaction of the user.

        Args:
            account_or_account_id (str): ID of the account for which to list
                the transactions OR account object.
            options (obj): further optional options
                accounts: comma separated list of account IDs.
                filter (obj) - Can take 4 possible keys:
                    - date (ISO date) - Transaction date
                    - person (str) - Payer or payee name
                    - purpose (str)
                    - amount (num)
                sync_id (str): Show only those items that have been created
                    within this synchronization.
                count (int): Limit the number of returned transactions.
                offset (int): Which offset into the result set should be used
                    to determine the first transaction to return (useful in
                    combination with count)
                sort (enum): ASC or DESC
                since (ISO date): Return only transactions after this date
                    based on since_type
                until (ISO date): This parameter can either be a transaction
                    ID or a date. Return only transactions which were booked
                    on or before
                since_type (enum): This parameter defines how the parameter
                    since will be interpreted. Possible values: "booked",
                    "created", "modified".
                types (enum): Comma separated list of transaction types used
                    for filtering. Possible values: "Transfer",
                    "Standing order", "Direct debit", "Salary or rent",
                    "GeldKarte", "Charges or interest".
                cents (bool): If true amounts will be shown in cents, Optional,
                    default: False
                include_pending (bool): This flag indicates whether pending
                    transactions should be included in the response. Pending
                    transactions are always included as a complete set,
                    regardless of the `since` parameter.
                include_statistics (bool): Includes statistics on the returned
                    transactions if true, Default: false.

        Returns:
            List of Transaction
        """
        allowed_keys = [
            "accounts",
            "filter",
            "sync_id",
            "count",
            "offset",
            "sort",
            "since",
            "until",
            "since_type",
            "types",
            "cents",
            "include_pending",
            "include_statistics",
        ]
        options = filter_none(filter_keys(options, allowed_keys))

        account_id = get_account_id(account_or_account_id)
        if account_id is not None:
            path = "/rest/accounts/{0}/transactions?{1}".format(
                account_id, urlencode(options)
            )
        else:
            path = "/rest/transactions?{0}".format(urlencode(options))

        return self._query_api_object(
            Transaction, path, collection_name="transactions"
        )

    def get_transaction(self, account_or_account_id, transaction_id, cents):
        """Retrieve a specific transaction.

        Args:
            account_or_account_id: account to be queried or its ID
            transaction_id: ID of the transaction to be retrieved
            cents (bool): If true amounts will be shown in cents, Optional,
                default: False

        Returns:
            Transaction object representing the transaction to be retrieved
        """
        options = {"cents": cents} if cents else {}

        account_id = get_account_id(account_or_account_id)
        if account_id is not None:
            path = "/rest/accounts/{0}/transactions/{1}?{2}".format(
                account_or_account_id, transaction_id, urlencode(options)
            )
        else:
            path = "/rest/transactions/{0}?{1}".format(
                transaction_id, urlencode(options)
            )

        return self._query_api_object(Transaction, path)

    @property
    def securities(self):
        """An array of `Security` objects, one for each transaction of
        the user.
        """
        return self._query_api_object(
            Security, "/rest/securities", collection_name="securities"
        )

    def get_securities(
        self,
        account_or_account_id=None,
        since=None,
        count=1000,
        offset=0,
        accounts=None,
    ):
        """Get an array of `Security` objects, one for each security of
        the user.

        Args:
            account_or_account_id: Account for which to list the securities or
                its ID
            since: this parameter can either be a transaction ID or a date
            count: limit the number of returned transactions
            offset: which offset into the result set should be used to
                determine the first transaction to return (useful in
                combination with count)
            accounts: if retrieving the securities for all accounts, filter
                the securities to be only from these accounts

        Returns:
            List of Security objects
        """
        params = {"count": count, "offset": offset}
        if accounts is not None and type(accounts) == list:
            params["accounts"] = ",".join(accounts)

        if since is not None:
            params["since"] = since

        params = urlencode(params)
        account_id = get_account_id(account_or_account_id)
        if account_id:
            query = "/rest/accounts/{0}/securities?{1}".format(
                account_id, params
            )
        else:
            query = "/rest/securities?{0}".format(params)

        return self._query_api_object(
            Security, query, collection_name="securities"
        )

    def get_security(self, account_or_account_id, security_id):
        """Retrieve a specific security.

        Args:
            account_or_account_id: account to be queried or its ID
            security_id: ID of the security to be retrieved

        Returns:
            Security object representing the transaction to be retrieved
        """

        query = "/rest/accounts/{0}/securities/{1}".format(
            get_account_id(account_or_account_id), security_id
        )
        return self._query_api_object(Security, query)

    def modify_security(
        self, account_or_account_id, security_or_security_id, visited=None
    ):
        """Modify a specific security.

        Args:
            account_or_account_id: account to be modified or its ID
            security_or_security_id: Security or its ID to be modified
            visited: new value of the visited field for the security

        Returns:
            Nothing if the request was successful
        """
        if isinstance(account_or_account_id, Account):
            account_or_account_id = account_or_account_id.account_id
        if isinstance(security_or_security_id, Security):
            security_or_security_id = security_or_security_id.security_id

        query = "/rest/accounts/{0}/securities/{1}".format(
            account_or_account_id, security_or_security_id
        )
        return self._request_with_exception(query, {"visited": visited}, "PUT")

    def modify_account_securities(self, account_or_account_id, visited=None):
        """
        Modify all securities of an account.

        Args:
            account_or_account_id: account to be modified or its ID
            visited: new value of the visited field for the security

        Returns:
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
        return self._request_with_exception(
            "/rest/securities", {"visited": visited}, "PUT"
        )

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
        return self._request_with_exception(
            "/rest/transactions", {"visited": visited}, "PUT"
        )

    def delete_transaction(
        self, account_or_account_id, transaction_or_transaction_id
    ):
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
            transaction_or_transaction_id = (
                transaction_or_transaction_id.transaction_id
            )

        query = "/rest/accounts/{0}/transactions/{1}".format(
            account_or_account_id, transaction_or_transaction_id
        )
        return self._request_with_exception(query, method="DELETE")

    def get_bank(self, bank_id):
        """Get bank.

        Args:
            bank_id: ID of the bank to be retrieved.

        Returns:
            BankContact object representing the bank to be retrieved
        """
        return self._query_api_object(BankContact, "/rest/banks/%s" % bank_id)

    def modify_bank(self, bank):
        """Modify a bank.

        Args:
            bank: modified bank object to be saved

        Returns:
            BankContact object for the updated bank
        """
        return self._query_api_object(
            BankContact,
            "/rest/banks/{0}".format(bank.bank_id),
            bank.dump(),
            "PUT",
        )

    def remove_bank_pin(self, bank_or_bank_id):
        """Remove the stored PIN for a bank (if there was one).

        Args:
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
        return self._request_with_exception("/rest/user", method="DELETE")

    def get_sync_url(self, state, redirect_uri):
        """URL to trigger a synchronization.

        The user should open this URL in a web browser to synchronize his/her
        accounts with the respective bank servers. When the process is
        finished, the user is redirected to the provided URL.

        Args:
            state: String passed on through the complete synchronization
                process and to the redirect target at the end. It should be
                used to validate the authenticity of the call to the redirect
                URL
            redirect_uri: URI the user is redirected to after the process
                completes

        Returns:
            the URL to be opened by the user.
        """
        response = self._request_with_exception(
            "/rest/sync",
            {"state": state, "redirect_uri": redirect_uri},
            method="POST",
        )
        if response is None:
            return None
        else:
            return (
                self.api_endpoint + "/task/start?id=" + response["task_token"]
            )

    def parse_webhook_notification(self, message_body):
        """Parse a webhook notification and get a WebhookNotification object.

        Args:
            message_body: message body of the webhook message (as string or
                dict)

        Returns:
            WebhookNotification object
        """
        if not isinstance(message_body, dict):
            message_body = json.loads(message_body)

        notification = WebhookNotification.from_dict(self, message_body)

        data = self._query_api(notification.observe_key)

        if re.match("/rest/transactions", notification.observe_key):
            notification.data = [
                Transaction.from_dict(self, transaction_dict)
                for transaction_dict in data["transactions"]
            ]

        elif re.match(
            "/rest/accounts/(.*)/transactions", notification.observe_key
        ):
            notification.data = [
                Transaction.from_dict(self, transaction_dict)
                for transaction_dict in data["transactions"]
            ]

        elif re.match("/rest/accounts/(.*)/balance", notification.observe_key):
            notification.data = AccountBalance.from_dict(data)

        return notification
