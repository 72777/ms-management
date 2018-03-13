import unittest
import uuid
from unittest.mock import patch, Mock

from requests import Response
from werkzeug.exceptions import InternalServerError, Unauthorized

import authentication.keyval as keyval
from authentication.api.auth_methods import FactionAuthAPI

MOCK_CMDB_HOST = 'http://cmdb/api'


def mock_os_getenv(key, default=None):
    if key == 'CMDB_HOST':
        return MOCK_CMDB_HOST
    else:
        return default


def mock_create_token(creds, priv_key, expire=None):
    return 'sometoken'


@patch('authentication.api.auth_methods.os.getenv', mock_os_getenv)
@patch('authentication.api.auth_methods.utils.create_jwt_token', mock_create_token)
class TestFactionBasicAuthMethod(unittest.TestCase):
    def setUp(self):
        self.fbam = FactionAuthAPI()

    @patch('authentication.api.auth_methods.requests')
    def test_login_cmdb_error(self, mock_r):
        mock_resp = Response()
        mock_resp.status_code = 500
        mock_resp.reason = 'Internal Server Error'
        mock_resp.json = Mock(return_value={'message': 'some error'})
        mock_r.get = Mock(return_value=mock_resp)
        creds = {
            'username': 'myusername@factioninc.com',
            'password': 'mypassword123'
        }
        self.assertRaises(InternalServerError, self.fbam.login, creds)

    @patch('authentication.api.auth_methods.requests')
    def test_login_user_not_found(self, mock_r):
        mock_resp = Response()
        mock_resp.status_code = 200
        mock_resp.json = Mock(return_value=[])
        mock_r.get = Mock(return_value=mock_resp)
        creds = {
            'username': 'myusername@factioninc.com',
            'password': 'mypassword123'
        }
        self.assertRaises(Unauthorized, self.fbam.login, creds)

    @patch('authentication.api.auth_methods.requests')
    def test_login_multiple_users_found(self, mock_r):
        mock_resp = Response()
        mock_resp.status_code = 200
        mock_resp.json = Mock(return_value=[
            {
                'identifier': str(uuid.uuid4()),
                'username': 'myusername@factioninc.com',
                'email': 'myusername@factioninc.com',
                'password': 'somehash',
                'authmethod': 'faction',
                'defaultorg': {
                    'identifier': 'someid',
                    'uri': 'someuri'
                },
                'contactMethods': [],
                'registrationState': 'registered',
            },
            {
                'identifier': str(uuid.uuid4()),
                'username': 'myusername@factioninc.com',
                'email': 'myusername@factioninc.com',
                'password': 'somehash',
                'authmethod': 'faction',
                'defaultorg': {
                    'identifier': 'someid',
                    'uri': 'someuri'
                },
                'contactMethods': [],
                'registrationState': 'registered',
            },
        ])
        mock_r.get = Mock(return_value=mock_resp)
        creds = {
            'username': 'myusername@factioninc.com',
            'password': 'mypassword123'
        }
        self.assertRaises(InternalServerError, self.fbam.login, creds)

    @patch('authentication.api.auth_methods.requests')
    def test_login_user_found_incorrect_password(self, mock_r):
        mock_resp = Response()
        mock_resp.status_code = 200
        mock_resp.json = Mock(return_value=[
            {
                'identifier': str(uuid.uuid4()),
                'username': 'myusername@factioninc.com',
                'email': 'myusername@factioninc.com',
                'password': 'somehash',
                'authmethod': 'faction',
                'defaultorg': {
                    'identifier': 'someid',
                    'uri': 'someuri'
                },
                'contactMethods': [],
                'registrationState': 'registered',
            },
        ])
        mock_r.get = Mock(return_value=mock_resp)
        creds = {
            'username': 'myusername@factioninc.com',
            'password': 'mypassword123'
        }
        self.assertRaises(Unauthorized, self.fbam.login, creds)

    @patch('authentication.api.auth_methods.requests')
    def test_login_user_in_pending_state(self, mock_r):
        mock_resp = Response()
        mock_resp.status_code = 200
        mock_resp.json = Mock(return_value=[
            {
                'identifier': str(uuid.uuid4()),
                'username': 'myusername@factioninc.com',
                'email': 'myusername@factioninc.com',
                'password': 'somehash',
                'authmethod': 'faction',
                'defaultorg': {
                    'identifier': 'someid',
                    'uri': 'someuri'
                },
                'contactMethods': [],
                'registrationState': 'pending',
            },
        ])
        mock_r.get = Mock(return_value=mock_resp)
        creds = {
            'username': 'myusername@factioninc.com',
            'password': 'mypassword123'
        }
        self.assertRaises(Unauthorized, self.fbam.login, creds)

    @patch('authentication.api.auth_methods.kv')
    @patch('authentication.api.auth_methods.utils.compare_pwd_with_hash')
    @patch('authentication.api.auth_methods.requests')
    def test_login_success(self, mock_r, mock_pwd_compare, mock_kv):
        mock_pwd_compare.return_value = True

        mock_resp = Response()
        mock_resp.status_code = 200
        mock_resp.json = Mock(return_value=
        [{
            'identifier': str(uuid.uuid4()),
            'username': 'myusername@factioninc.com',
            'email': 'myusername@factioninc.com',
            'password': 'somehash',
            'authmethod': 'faction',
            'defaultorg': {
                'identifier': 'someid',
                'uri': 'someuri'
            },
            'contactMethods': [],
            'registrationState': 'registered',
        }])
        mock_r.get = Mock(return_value=mock_resp)
        creds = {
            'username': 'myusername@factioninc.com',
            'password': 'mypassword123'
        }
        resp = self.fbam.login(creds)
        self.assertTrue('token' in resp.keys())
        self.assertTrue('user' in resp.keys())
        self.assertTrue('organization' in resp.keys())

    # Logout
    @patch('authentication.api.auth_methods.kv')
    def test_logout_token_not_found(self, mock_kv):
        mock_kv.get = Mock(side_effect=keyval.KeyValueError('', ''))
        self.assertIsNone(self.fbam.logout('sometoken'))

    @patch('authentication.api.auth_methods.kv')
    def test_logout_success(self, mock_kv):
        mock_kv.get = Mock(return_value='{}')
        mock_kv.delete = Mock(return_value=None)
        self.fbam.logout('sometoken')
