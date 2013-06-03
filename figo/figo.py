#
#  Created by Stefan Richter on 2013-01-12.
#  Copyright (c) 2013 figo GmbH. All rights reserved.
#

import hashlib
import httplib
from itertools import izip_longest
import json
import logging
import socket
import ssl
import sys
import urllib


from .models import Account, Notification, Transaction


logger = logging.getLogger(__name__)


class VerifiedHTTPSConnection(httplib.HTTPSConnection):
    """HTTPSConnection supporting certificate authentication based on fingerprint"""
    
    VALID_FINGERPRINTS = ("A6:FE:08:F4:A8:86:F9:C1:BF:4E:70:0A:BD:72:AE:B8:8E:B7:78:52",
                          "AD:A0:E3:2B:1F:CE:E8:44:F2:83:BA:AE:E4:7D:F2:AD:44:48:7F:1E")
    
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
            fingerprint = ":".join(["".join(x) for x in izip_longest(*[iter(fingerprint.upper())]*2)])
            if not fingerprint in VerifiedHTTPSConnection.VALID_FINGERPRINTS:
                raise ssl.SSLError("Certificate validation failed")


class FigoException(Exception):
    """Base class for all exceptions transported via the figo connect API.

    They consist of a code-like `error` and a human readable `error_description`.
    """

    def __init__(self, error, error_description):
        self.error = error
        self.error_description = error_description

    @classmethod
    def from_dict(cls, dictionary):
        return cls(dictionary['error'], dictionary['error_description'])


class FigoConnection(object):
    """Representing a not user-bound connection to the figo connect API.

    Its main purpose is to let user login via the OAuth2 API.
    """

    API_ENDPOINT = "api.leanbank.com"
    API_SECURE = True

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
            return {'error': "access_denied", 'error_description': "Access Denied"}
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
        return self.API_ENDPOINT + "/auth/code?" + urllib.urlencode({'response_type': 'code', 'client_id': self.client_id, 'redirect_uri': self.redirect_uri, 'scope': scope, 'state': state})

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

        response = self._query_api("/auth/token", data={'code': authorization_code, 'redirect_uri': self.redirect_uri, 'grant_type': 'authorization_code'})
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

        response = self._query_api("/auth/token", data={'refresh_token': refresh_token, 'redirect_uri': self.redirect_uri, 'grant_type': 'refresh_token'})
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

        response = self._query_api("/auth/revoke?" + urllib.urlencode({'token': access_token_info['refresh_token']}))
        if 'error' in response:
            raise FigoException.from_dict(response)


class FigoSession(object):
    """Represents a user-bound connection to the figo connect API and allows access to the users data"""

    def __init__(self, access_token):
        """Creates a FigoSession instance.

        :Parameters:
         - `access_token` - the access token to bind this session to a user
        """
        self.access_token = access_token

    def _query_api(self, path, data=None, method="GET"):
        """Helper method for making a REST-compliant API call

        :Parameters:
         - `path` - path on the server to call
         - `data` - Dictionary of data to send to the server in message body
         - `method` - HTTP verb to use for the request

        :Returns:
            the JSON-parsed result body
        """

        connection = VerifiedHTTPSConnection(FigoConnection.API_ENDPOINT) if FigoConnection.API_SECURE else httplib.HTTPConnection(FigoConnection.API_ENDPOINT)
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
            return {'error': "access_denied", 'error_description': "Access Denied"}
        elif response.status == 404:
            return None
        else:
            logger.warn("Querying the API failed when accessing '%s': %d", path, response.status)
            return {'error': "internal_server_error", 'error_description': "We are very sorry, but something went wrong"}

    @property
    def accounts(self):
        """An array of `Account` objects, one for each account the user has granted the app access"""

        response = self._query_api("/rest/accounts")
        if 'error' in response:
            raise FigoException.from_dict(response)
        return [Account.from_dict(self, account_dict) for account_dict in response['accounts']]

    def get_account(self, account_id):
        """Retrieve a specific account.

        :Parameters:
         - `account_id` - ID of the account to be retrieved

        :Returns:
            `Account` object for the respective account
        """

        response = self._query_api("/rest/accounts/" + str(account_id))
        if 'error' in response:
            raise FigoException.from_dict(response)
        return Account.from_dict(self, response)

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

    def add_notification(self, **kwargs):
        """Create a new notification.

        :Parameters:
            all Notification attributes as keyword arguments

        :Returns:
            ID of the newly created notification
        """

        response = self._query_api("/rest/notifications", kwargs, method="POST")
        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return response['notification_id']

    def modify_notification(self, notification_id, **kwargs):
        """Modify a notification.

        :Parameters:
         - `notification_id` - ID of the notification to be modified
         - all Notification attributes as keyword arguments
        """

        response = self._query_api("/rest/notifications/" + str(notification_id), kwargs, method="PUT")
        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)

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
    def transactions(self):
        """An array of `Transaction` objects, one for each transaction of the user"""

        response = self._query_api("/rest/transactions")
        if response is None:
            return None
        elif 'error' in response:
            raise FigoException.from_dict(response)
        else:
            return [Transaction.from_dict(self, transaction_dict) for transaction_dict in response['transactions']]

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
