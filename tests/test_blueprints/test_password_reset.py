import uuid
from unittest import TestCase
from unittest.mock import patch, Mock

import requests
from requests import Response
from werkzeug.exceptions import Unauthorized, BadRequest

import services.exceptions.exceptions as exceptions
from authentication.blueprints.password import ResetPassword
from authentication.keyval import KeyValueError

MOCK_RABBIT_HOST = 'amqp://rabbit:5672'
MOCK_NOTIFIER_HOST = 'http://abc/notifier'
MOCK_CMDB_HOST = 'http://cmdb/api'
MOCK_AUTH_PRIV_KEY = '3432'


def mock_os_getenv(key, default=None):
    if key == 'RABBIT_HOST':
        return MOCK_RABBIT_HOST
    elif key == 'NOTIFIER_HOST':
        return MOCK_NOTIFIER_HOST
    elif key == 'CMDB_HOST':
        return MOCK_CMDB_HOST
    elif key == 'AUTH_PRIV_KEY':
        return MOCK_AUTH_PRIV_KEY
    else:
        return default


def mock_create_token(creds, key, expire=None):
    return 'sometoken'


class MockException(Exception):
    pass


@patch('authentication.amqp.listeners.os.getenv', mock_os_getenv)
@patch('authentication.api.auth_methods.create_jwt_token', mock_create_token)
class TestResetPassword(TestCase):
    def setUp(self):
        self.rp = ResetPassword()

    @patch('authentication.api.auth_methods.requests')
    @patch('authentication.blueprints.password.flask')
    @patch('authentication.blueprints.password.kv')
    def test_post_success(self, mock_kv, mock_flask, mock_r):
        mock_kv.get = Mock()
        mock_kv.get.return_value = 'token'

        mock_flask.request.get_json = Mock(return_value={'newpassword': 'S0m3_V@lid_P@ssw0rd', 'verifypassword': 'S0m3_V@lid_P@ssw0rd'})

        mock_resp = Response()
        mock_resp.status_code = 200
        mock_resp.json = Mock(return_value=[{
            'identifier': str(uuid.uuid4()),
            'username': 'test@factioninc.com',
            'email': 'test@factioninc.com',
            'password': 'S0m3_V@lid_P@ssw0rd',
            'defaultorg': {
                'identifier': str(uuid.uuid4()),
                'uri': '/api/general/organizations/123'
            },
            'registrationstate': 'pending',
            'contactmethods': [],
            'tags': None
        }])
        mock_get_password_history_resp = Response()
        mock_get_password_history_resp.status_code = 200
        mock_get_password_history_resp.json = Mock(return_value=[{
            'identifier': str(uuid.uuid4()),
            'user': str(uuid.uuid4()),
            'password': '!!!password!!!ABC'
        }])
        mock_r.get = Mock(side_effect=[mock_resp, mock_get_password_history_resp])

        mock_put_resp = Response()
        mock_put_resp.status_code = 200
        mock_put_resp.json = Mock(return_value={
            'identifier': str(uuid.uuid4()),
            'username': 'test@factioninc.com',
            'email': 'test@factioninc.com',
            'password': 'S0m3_V@lid_P@ssw0rd',
            'defaultorg': {
                'identifier': str(uuid.uuid4()),
                'uri': '/api/general/organizations/123'
            },
            'registrationstate': 'registered',
            'contactmethods': []
        })
        mock_r.put = Mock(return_value=mock_put_resp)
        resp = self.rp.post('token')
        self.assertTrue('message' in resp.keys())

    @patch('authentication.blueprints.password.flask')
    @patch('authentication.blueprints.password.kv')
    def test_post_token_not_in_keyval(self, mock_kv, mock_flask):
        mock_kv.get = Mock()
        mock_kv.get.side_effect = KeyValueError('', '')
        self.assertRaises(Unauthorized, self.rp.post, '123')

    @patch('authentication.blueprints.password.flask')
    @patch('authentication.blueprints.password.kv')
    def test_post_passwords_dont_match(self, mock_kv, mock_flask):
        mock_kv.get = Mock()
        mock_kv.get.return_value = 'token'

        mock_flask.request.get_json = Mock(return_value={'newpassword': 'mypass', 'verifypassword': 'mynewpass'})
        self.assertRaises(BadRequest, self.rp.post, 'token')

    @patch('authentication.api.auth_methods.requests.get')
    @patch('authentication.blueprints.password.flask')
    @patch('authentication.blueprints.password.kv')
    def test_post_cmdb_user_not_found(self, mock_kv, mock_flask, mock_r_get):
        mock_kv.get = Mock()
        mock_kv.get.return_value = 'token'

        mock_flask.request.get_json = Mock(return_value={'newpassword': 'S0m3_V@lid_P@ssw0rd', 'verifypassword': 'S0m3_V@lid_P@ssw0rd'})

        mock_resp = Response()
        mock_resp.status_code = 200
        mock_r_get.side_effect = requests.HTTPError('')
        self.assertRaises(exceptions.FactionAPIError, self.rp.post, 'token')

    @patch('authentication.api.auth_methods.requests.put')
    @patch('authentication.api.auth_methods.requests.get')
    @patch('authentication.blueprints.password.flask')
    @patch('authentication.blueprints.password.kv')
    def test_post_cmdb_failed_to_update_user(self, mock_kv, mock_flask, mock_r_get, mock_r_put):
        mock_kv.get = Mock()
        mock_kv.get.return_value = 'token'

        mock_flask.request.get_json = Mock(return_value={'newpassword': 'S0m3_V@lid_P@ssw0rd', 'verifypassword': 'S0m3_V@lid_P@ssw0rd'})

        mock_resp = Response()
        mock_resp.status_code = 200
        mock_resp.json = Mock(return_value=[{
            'identifier': str(uuid.uuid4()),
            'username': 'test@factioninc.com',
            'email': 'test@factioninc.com',
            'password': 'somepwd',
            'defaultorg': {
                'identifier': str(uuid.uuid4()),
                'uri': '/api/general/organizations/123'
            },
            'registrationstate': 'pending',
            'contactmethods': []
        }])
        mock_r_get.return_value = mock_resp

        mock_put_resp = Response()
        mock_put_resp.status_code = 400
        mock_put_resp.json = Mock(return_value={
            'message': 'some error'
        })
        mock_r_put.return_value = mock_put_resp

        self.assertRaises(exceptions.FactionAPIError, self.rp.post, 'token')

    @patch('authentication.blueprints.password.flask')
    @patch('authentication.blueprints.password.kv')
    def test_post_password_length_not_met(self, mock_kv, mock_flask):
        mock_kv.get = Mock()
        mock_kv.get.return_value = 'token'

        mock_flask.request.get_json = Mock(return_value={'newpassword': 'N0tL0ng', 'verifypassword': 'N0tL0ng'})
        self.assertRaises(BadRequest, self.rp.post, 'token')

    @patch('authentication.blueprints.password.flask')
    @patch('authentication.blueprints.password.kv')
    def test_post_password_no_uppercase(self, mock_kv, mock_flask):
        mock_kv.get = Mock()
        mock_kv.get.return_value = 'token'

        mock_flask.request.get_json = Mock(return_value={'newpassword': 'n0upp3rc@ase', 'verifypassword': 'n0upp3rc@ase'})
        self.assertRaises(BadRequest, self.rp.post, 'token')

    @patch('authentication.blueprints.password.flask')
    @patch('authentication.blueprints.password.kv')
    def test_post_password_no_lowercase(self, mock_kv, mock_flask):
        mock_kv.get = Mock()
        mock_kv.get.return_value = 'token'

        mock_flask.request.get_json = Mock(return_value={'newpassword': 'N0L0W3R%%C@S3', 'verifypassword': 'N0L0W3R%%C@S3'})
        self.assertRaises(BadRequest, self.rp.post, 'token')

    @patch('authentication.blueprints.password.flask')
    @patch('authentication.blueprints.password.kv')
    def test_post_password_no_special_chars(self, mock_kv, mock_flask):
        mock_kv.get = Mock()
        mock_kv.get.return_value = 'token'

        mock_flask.request.get_json = Mock(return_value={'newpassword': 'noSPECIALchars', 'verifypassword': 'noSPECIALchars'})
        self.assertRaises(BadRequest, self.rp.post, 'token')

    @patch('authentication.api.auth_methods.compare_pwd_with_hash')
    @patch('authentication.api.auth_methods.requests.get')
    @patch('authentication.blueprints.password.flask')
    @patch('authentication.blueprints.password.kv')
    def test_post_password_failed_history_check(self, mock_kv, mock_flask, mock_r_get, mock_compare):
        mock_kv.get = Mock()
        mock_kv.get.return_value = 'token'

        mock_flask.request.get_json = Mock(return_value={'newpassword': 'S0m3_V@lid_P@ssw0rd', 'verifypassword': 'S0m3_V@lid_P@ssw0rd'})

        mock_resp = Response()
        mock_resp.status_code = 200
        mock_resp.json = Mock(return_value=[{
            'identifier': str(uuid.uuid4()),
            'username': 'test@factioninc.com',
            'email': 'test@factioninc.com',
            'password': 'S0m3_V@lid_P@ssw0rd',
            'defaultorg': {
                'identifier': str(uuid.uuid4()),
                'uri': '/api/general/organizations/123'
            },
            'registrationstate': 'pending',
            'contactmethods': [],
            'tags': None
        }])
        mock_get_password_history_resp = Response()
        mock_get_password_history_resp.status_code = 200
        mock_get_password_history_resp.json = Mock(return_value=[{
            'identifier': str(uuid.uuid4()),
            'user': str(uuid.uuid4()),
            'password': '!!!password!!!ABC'
        }])
        mock_r_get.side_effect = [mock_resp, mock_get_password_history_resp]

        # When comparing passwords, return true
        mock_compare.return_value = True

        self.assertRaises(exceptions.FactionAPIError, self.rp.post, 'token')
