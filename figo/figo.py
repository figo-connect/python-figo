import base64
import json
import logging
import os
import re
from datetime import datetime, timedelta
from urllib.parse import urlencode

from dotenv import load_dotenv
from requests import Session

# TODO: We need verify which of this unused import can be remove from SDK
from .exceptions import ERROR_MESSAGES, FigoException
from .models import (  # noqa: F401
    Account,
    AccountBalance,
    Category,
    Challenge,
    Credential,
    LoginSettings,
    Notification,
    Payment,
    Security,
    StandingOrder,
    Sync,
    SynchronizationStatus,
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
            "User-Agent": f"python_figo/{__version__}",
        }
        self.language = language
        self.api_endpoint = api_endpoint

    @staticmethod
    def _has_error(response):
        return "error" in response and response["error"]

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
        complete_path = f"{self.api_endpoint}{path}"

        session = Session()
        session.headers.update(self.headers)

        try:
            response = session.request(method, complete_path, json=data)
        except Exception as err:
            response = None
            status_code = 500
            logger.error(
                "Request {} '{}'  raise error: {}".format(
                    method, complete_path, err
                )
            )
        else:
            status_code = response.status_code
            logger.debug(
                "{} '{}' result with status {} and text: {}".format(
                    method, complete_path, status_code, response.text[:2000],
                )
            )
        finally:
            session.close()

        if response is None or response.text == "":
            res_data = {}
        else:
            try:
                res_data = response.json()
            except Exception as err:
                logger.error(
                    "Convert data to JSON format failed: {}".format(err)
                )
                # TODO: should we return here also error or raise this
                #  exception?
                res_data = {}

        if 200 <= status_code < 300:
            logger.debug("Response data returned: {}".format(res_data))
        elif self._has_error(res_data):
            if raise_exception:
                logger.error(
                    "Raise FigoException for response status code {}".format(
                        status_code,
                    ),
                )
                raise FigoException.from_dict(
                    res_data, status_code=status_code
                )
            logger.debug(
                "Response data with errors returned: {}".format(res_data)
            )
        elif status_code == 500:
            logger.error(
                "Querying the API failed when accessing {}: {}".format(
                    complete_path, status_code,
                ),
            )
            res_data = {"error": ERROR_MESSAGES[status_code]}
        elif status_code in ERROR_MESSAGES:
            logger.debug(
                "Error dict returned for status: {}".format(status_code)
            )
            res_data = {"error": ERROR_MESSAGES[response.status_code]}

        return res_data

    def _request_with_exception(self, path, data=None, method="GET"):
        """Helper to trigger raise exception on _request_api"""
        return self._request_api(path, data, method, raise_exception=True)

    def _process_model_list(self, entities, model, is_session=True):
        """Helper to proceed lost of entities for target model using
        `from_dict` method
        """
        session = self if is_session else None
        return [model.from_dict(session, entity) for entity in entities]

    def _process_catalog_list(self, entities, is_session=True):
        """Helper to proceed list of entities for catalog."""
        return self._process_model_list(entities, LoginSettings, is_session)

    def _query_api_object(
        self, model, path, data=None, method="GET", collection_name=None
    ):
        """Helper method using _request_with_exception but encapsulating the
        result as an object.
        """
        res_data = self._request_with_exception(path, data, method)
        if not res_data:
            return None
        elif collection_name is None:
            return model.from_dict(self, res_data)
        elif collection_name == "collection":
            # Some collections in the API response ARE NOT embedded in
            # collection name. (Ex: challenges, accesses)
            return self._process_model_list(res_data, model)
        else:
            return self._process_model_list(res_data[collection_name], model)

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
        basic_auth = f"{self.client_id}:{self.client_secret}".encode("ascii")
        basic_auth_encoded = base64.b64encode(basic_auth).decode("utf-8")
        self.headers.update({"Authorization": f"Basic {basic_auth_encoded}"})

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
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "scope": scope,
                "state": state,
            }
        )
        return f"{self.api_endpoint}/auth/code?{query}"

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

        res_data = self._request_with_exception(
            "/auth/token",
            data={
                "code": authentication_code,
                "redirect_uri": self.redirect_uri,
                "grant_type": "authorization_code",
            },
            method="POST",
        )

        expire_dt = datetime.now() + timedelta(seconds=res_data["expires_in"])
        return {
            "access_token": res_data["access_token"],
            "refresh_token": res_data.get("refresh_token"),
            "expires": expire_dt,
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

        res_data = self._request_with_exception(
            "/auth/token", data, method="POST"
        )

        expire_dt = datetime.now() + timedelta(seconds=res_data["expires_in"])
        return {
            "access_token": res_data["access_token"],
            "refresh_token": res_data.get("refresh_token"),
            "expires": expire_dt,
            "scope": res_data["scope"],
        }

    # TODO: Missing unit test but used in ownly-backend
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
        res_data = self._request_with_exception(
            "/auth/token", data=data, method="POST"
        )

        expire_dt = datetime.now() + timedelta(seconds=res_data["expires_in"])
        return {
            "access_token": res_data["access_token"],
            "expires": expire_dt,
        }

    # TODO: Missing unit test but used in ownly-backend
    def revoke_token(self, token):
        """Revoke a granted access or refresh token and thereby invalidate it.

        Note: this action has immediate effect, i.e. you will not be able use
            that token anymore after this call.

        Args:
            token: access or refresh token to be revoked
        """
        options = urlencode({"token": token})
        return self._request_with_exception(f"/auth/revoke?{options}")

    def add_user(self, name, email, password, language="de"):
        """Create a new figo Account.

        Args:
            name: Full name
            email: Email address; It must obey the figo username & password
                policy
            password: New figo Account password; It must obey the figo
                username & password policy
            language: Two-letter code of preferred language

        Returns:
            Auto-generated recovery password.
        """
        data = {
            "full_name": name,
            "email": email,
            "password": password,
            "language": language,
        }
        return self._request_with_exception(
            "/auth/user", data=data, method="POST",
        )

    def get_version(self):
        """Returns the version of the API."""
        return self._request_with_exception("/version")

    # TODO: Review test cases and extend them about entity_type
    def get_catalog(self, q=None, country_code='de', entity_type=None):
        """Return a dict with lists of supported banks and payment services,
        with client auth.

        Returns:
            dict {"banks": [LoginSettings], "services": [LoginSettings]}:
                dict with lists of supported banks and payment services
            or list with target entity types when it has been chosen:
                [LoginSettings]
        """
        options = urlencode(filter_none({"country": country_code, "q": q}))
        catalog = self._request_with_exception(f"/catalog?{options}")

        if entity_type:
            # working with "banks" and "services"
            entities = catalog.get(entity_type)
            if entities:
                return self._process_catalog_list(entities, is_session=False)

        for k, v in catalog.items():
            catalog[k] = self._process_catalog_list(v, is_session=False)

        return catalog

    # Custom Categories
    # (https://docs.finx.finleap.cloud/stable/#tag/Custom-Categories):

    # TODO: Custom Categories are not implemented - do we need them?


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
        self.headers.update({"Authorization": f"Bearer {self.access_token}"})
        self.sync_poll_retry = sync_poll_retry

    # User management
    # (https://docs.finx.finleap.cloud/stable/#tag/User-Management):

    @property
    def user(self):
        """Get the current figo Account.

        Returns:
            User object for the current figo Account
        """
        return self._query_api_object(User, "/rest/user")

    # TODO: Missing test cases
    # TODO: Is different User available to create or modify different user?
    #  If not we shouldn't use here parameter user, but property directly in
    #  method?
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

    # Catalog user auth (https://docs.finx.finleap.cloud/stable/#tag/Catalog):

    def get_catalog(self, country_code=None):
        """Return a dict with lists of supported banks and payment services.

        Returns:
            dict {"banks": [LoginSettings], "services": [LoginSettings]}:
                dict with lists of supported banks and payment services
        """
        options = urlencode(filter_none({"country": country_code}))

        catalog = self._request_with_exception(f"/rest/catalog?{options}")

        for k, v in catalog.items():
            catalog[k] = self._process_catalog_list(v)
        return catalog

    # TODO: Missing unit test but used in ownly-backend
    # TODO: Maybe we should use directly FigoBank instead of this method.
    # TODO: Looks like this is more FigoConnection method
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
            f"/catalog/banks?{query_params}",
            collection_name="collection",
        )
        if len(response) > 0:
            return response[0]

        err_msg = f"Login settings for bank {item_id} were not found"
        raise FigoException(
            error="login_settings_not_found", error_description=err_msg
        )

    # Accesses (https://docs.finx.finleap.cloud/stable/#tag/Accesses):

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
        return self._request_with_exception("/rest/accesses", data, "POST")

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
        return self._request_with_exception(f"/rest/accesses/{access_id}")

    def remove_pin(self, access_id):
        """Remove a PIN from the API backend that has been previously stored
        for automatic synchronization or ease of use.

        Args:
            access_id (str): figo ID of the provider access. [required]

        Returns:
            Access object for which the PIN was removed
        """
        return self._request_with_exception(
            f"/rest/accesses/{access_id}/remove_pin", method="POST"
        )

    # Synchronizations
    # (https://docs.finx.finleap.cloud/stable/#tag/Synchronizations):

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
        path = f"/rest/accesses/{access_id}/syncs"
        return self._query_api_object(Sync, path, data=data, method="POST")

    def get_synchronization_status(self, access_id, sync_id):
        """Get synchronization status.

        Args:
            access_id (str): figo ID of the provider access, Required
            sync_id (str): figo ID of the synchronization operation, Required

        Returns:
            Object: synchronization operation.
        """
        return self._query_api_object(
            Sync, f"/rest/accesses/{access_id}/syncs/{sync_id}"
        )

    # Strong Customer Authentication - SCA / 2FA
    # (https://docs.finx.finleap.cloud/stable/#tag/Strong-Customer-Authentication):

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
            f"/rest/accesses/{access_id}/syncs/{sync_id}/challenges",
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
        path = (
            f"/rest/accesses/{access_id}/syncs/{sync_id}/challenges/"
            f"{challenge_id}"
        )
        return self._query_api_object(Challenge, path)

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
        path = (
            f"/rest/accesses/{access_id}/syncs/{sync_id}/challenges/"
            f"{challenge_id}/response"
        )
        return self._request_with_exception(path, data, "POST")

    # Accounts (https://docs.finx.finleap.cloud/stable/#tag/Accounts):

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
        account_id = get_account_id(account_or_account_id)
        return self._query_api_object(Account, f"/rest/accounts/{account_id}")

    def get_accounts(self):
        """Get list of bank accounts.

        Returns:
            List of Accounts accessible from Token
        """
        return self._query_api_object(
            Account, "/rest/accounts", collection_name="accounts",
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
            f"/rest/accounts/{account.account_id}",
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

    def get_account_balance(self, account_or_account_id):
        """Get balance and account limits.

        Args:
            account_or_account_id: account to be queried or its ID

        Returns:
            AccountBalance object for the respective account
        """
        account_id = get_account_id(account_or_account_id)
        path = f"/rest/accounts/{account_id}/balance"
        return self._query_api_object(AccountBalance, path)

    # Transactions (https://docs.finx.finleap.cloud/stable/#tag/Transactions):

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
        options = urlencode(filter_none(filter_keys(options, allowed_keys)))

        account_id = get_account_id(account_or_account_id)
        if account_id is not None:
            path = f"/rest/accounts/{account_id}/transactions?{options}"
        else:
            path = f"/rest/transactions?{options}"

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
        options = urlencode(options)

        account_id = get_account_id(account_or_account_id)
        if account_id is not None:
            path = (
                f"/rest/accounts/{account_id}/transactions/{transaction_id}"
                f"?{options}"
            )
        else:
            path = f"/rest/transactions/{transaction_id}?{options}"

        return self._query_api_object(Transaction, path)

    def modify_account_transactions(self, account_or_account_id, visited=None):
        """Modify all transactions of a specific account.

        Args:
            account_or_account_id: account to be modified or its ID
            visited: new value of the visited field for the transactions

        Returns:
            Nothing if the request was successful
        """
        account_id = get_account_id(account_or_account_id)
        path = f"/rest/accounts/{account_id}/transactions"
        return self._request_with_exception(path, {"visited": visited}, "PUT")

    def modify_user_transactions(self, visited=None):
        """Modify all transactions of the current user.

        Args:
            visited: new value of the visited field for the transactions

        Returns:
            Nothing if the request was successful
        """
        path = "/rest/transactions"
        return self._request_with_exception(path, {"visited": visited}, "PUT")

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
        account_id = get_account_id(account_or_account_id)
        if isinstance(transaction_or_transaction_id, Transaction):
            transaction_or_transaction_id = (
                transaction_or_transaction_id.transaction_id
            )

        path = (
            f"/rest/accounts/{account_id}/transactions/"
            f"{transaction_or_transaction_id}"
        )
        return self._request_with_exception(path, method="DELETE")

    # Payments (https://docs.finx.finleap.cloud/stable/#tag/Payments):

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
        options = urlencode(options)

        account_id = get_account_id(account_or_account_id)
        if account_id:
            uri = f"/rest/accounts/{account_id}/payments?{options}"
        else:
            uri = f"/rest/payments?{options}"

        return self._query_api_object(Payment, uri, collection_name="payments")

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
        options = urlencode(options)
        account_id = get_account_id(account_or_account_id)
        path = f"/rest/accounts/{account_id}/payments/{payment_id}?{options}"
        return self._query_api_object(Payment, path)

    def add_payment(self, payment):
        """Create a new payment.

        Args:
            payment: payment to be created. It should not have its payment_id
                set.

        Returns:
            Payment object of the newly created payment as returned by the
                server
        """
        data = payment.dump()
        path = f"/rest/accounts/{payment.account_id}/payments"
        return self._query_api_object(Payment, path, data, "POST")

    def modify_payment(self, payment):
        """Modify a payment.

        Args:
            payment: modified payment object to be modified

        Returns:
            Payment object for the updated payment
        """
        data = payment.dump()
        path = (
            f"/rest/accounts/{payment.account_id}/payments/"
            f"{payment.payment_id}"
        )
        return self._query_api_object(Payment, path, data, "PUT")

    def remove_payment(self, payment):
        """Remove a payment.

        Args:
            payment: payment to be removed
        """
        path = (
            f"/rest/accounts/{payment.account_id}/payments/"
            f"{payment.payment_id}"
        )
        self._request_with_exception(path, method="DELETE")

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

        path = (
            f"/rest/accounts/{payment.account_id}/payments/"
            f"{payment.payment_id}/init"
        )
        response = self._request_with_exception(path, params, "POST")
        return response

    def get_payment_status(self, payment, init_id):
        """Get initiation status for  payment initiated to bank server.

        Args:
            payment: payment to be retrieved the status for, Required
            init_id: initiation id, Required

        Returns:
            the initiation status of the payment
        """
        path = (
            f"/rest/accounts/{payment.account_id}/payments/"
            f"{payment.payment_id}/init/{init_id}"
        )
        return self._request_with_exception(path)

    def get_payment_challenges(
        self, account_or_account_id, payment_id, init_id
    ):
        """List payment challenges.
        https://docs.finx.finleap.cloud/stable/#operation/listPaymentChallenges

        Args:
            account_or_account_id: account to be queried or its ID, Required
            payment: payment to be retrieved the status for, Required
            init_id: initiation id, Required

        Returns:
            List of challenges for the required payment
        """
        account_id = get_account_id(account_or_account_id)
        path = (
            f"/rest/accounts/{account_id}/payments/{payment_id}/init/{init_id}"
            f"/challenges"
        )
        return self._query_api_object(Challenge, path)

    def get_payment_challenge(
        self, account_or_account_id, payment_id, init_id, challenge_id
    ):
        """Get payment challenge.
        https://docs.finx.finleap.cloud/stable/#operation/getPaymentChallenge

        Args:
            account_or_account_id: account to be queried or its ID, Required
            payment: payment to be retrieved the status for, Required
            init_id: initiation id, Required
            challenge_id: challenge id, Required

        Returns:
            Challenge: The required challenge for the payment
        """
        account_id = get_account_id(account_or_account_id)
        path = (
            f"/rest/accounts/{account_id}/payments/{payment_id}/init/{init_id}"
            f"/challenges/{challenge_id}"
        )
        return self._query_api_object(Challenge, path)

    def solve_payment_challenges(
        self, account_or_account_id, payment_id, init_id, challenge_id, payload
    ):
        """Get payment challenge.
        https://docs.finx.finleap.cloud/stable/#operation/solvePaymentChallenge

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

    # Standing Orders
    # (https://docs.finx.finleap.cloud/stable/#tag/Standing-Orders):

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
        options = urlencode(options)

        account_id = get_account_id(account_or_account_id)
        if account_id:
            path = f"/rest/accounts/{account_id}/standing_orders?{options}"
        else:
            path = f"/rest/standing_orders?{options}"

        return self._query_api_object(
            StandingOrder, path, collection_name="standing_orders"
        )

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
        options = urlencode(options)
        account_id = get_account_id(account_or_account_id)
        if account_id:
            path = (
                f"/rest/accounts/{account_id}/standing_orders/"
                f"{standing_order_id}?{options}"
            )
        else:
            path = f"/rest/standing_orders/{standing_order_id}?{options}"

        return self._query_api_object(StandingOrder, path)

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
            path = (
                f"/rest/accounts/{account_id}/standing_orders/"
                f"{standing_order_id}"
            )
        else:
            path = f"/rest/standing_orders/{standing_order_id}"

        self._request_with_exception(path, method="DELETE")

    # Securities (https://docs.finx.finleap.cloud/stable/#tag/Securities):

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
        accounts = ",".join(accounts) if isinstance(accounts, list) else None
        options = {
            "count": count,
            "offset": offset,
            "since": since,
            "accounts": accounts,
        }
        options = filter_none(options)
        options = urlencode(options)
        account_id = get_account_id(account_or_account_id)
        if account_id:
            path = f"/rest/accounts/{account_id}/securities?{options}"
        else:
            path = f"/rest/securities?{options}"

        return self._query_api_object(
            Security, path, collection_name="securities"
        )

    def get_security(self, account_or_account_id, security_id):
        """Retrieve a specific security.

        Args:
            account_or_account_id: account to be queried or its ID
            security_id: ID of the security to be retrieved

        Returns:
            Security object representing the transaction to be retrieved
        """
        account_id = get_account_id(account_or_account_id)
        query = f"/rest/accounts/{account_id}/securities/{security_id}"
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
        account_id = get_account_id(account_or_account_id)
        if isinstance(security_or_security_id, Security):
            security_or_security_id = security_or_security_id.security_id

        path = (
            f"/rest/accounts/{account_id}/securities/{security_or_security_id}"
        )
        return self._request_with_exception(path, {"visited": visited}, "PUT")

    def modify_account_securities(self, account_or_account_id, visited=None):
        """
        Modify all securities of an account.

        Args:
            account_or_account_id: account to be modified or its ID
            visited: new value of the visited field for the security

        Returns:
            Nothing if the request was successful
        """
        account_id = get_account_id(account_or_account_id)
        path = f"/rest/accounts/{account_id}/securities"
        return self._request_with_exception(path, {"visited": visited}, "PUT")

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

    # Financial Timeline
    # (https://docs.finx.finleap.cloud/stable/#tag/Financial-Timeline):

    # TODO: Financial Timeline is not implemented - do we need them?

    # Aggregations (https://docs.finx.finleap.cloud/stable/#tag/Aggregations):

    # TODO: Aggregations are not implemented - do we need them?

    # Contracts (https://docs.finx.finleap.cloud/stable/#tag/Contracts):

    # TODO: Contracts are not implemented - do we need them?

    # Notifications
    # (https://docs.finx.finleap.cloud/stable/#tag/Notifications):

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

        path = f"/rest/notifications/{notification_or_notification_id}"
        self._request_with_exception(path, method="DELETE")

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

        data = self._request_with_exception(notification.observe_key)

        if re.match("/rest/transactions", notification.observe_key):
            notification.data = self._process_model_list(
                data["transactions"], Transaction
            )
        elif re.match(
            "/rest/accounts/(.*)/transactions", notification.observe_key
        ):

            notification.data = self._process_model_list(
                data["transactions"], Transaction
            )
        elif re.match("/rest/accounts/(.*)/balance", notification.observe_key):
            notification.data = AccountBalance.from_dict(data)

        return notification
