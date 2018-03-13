import uuid
from unittest import TestCase
from unittest.mock import patch, Mock

from requests import Response

from authentication.amqp.listeners import OrgUserRoleListener

MOCK_RABBIT_HOST = "amqp://rabbit:5672"
MOCK_NOTIFIER_HOST = "http://abc/notifier"
MOCK_CMDB_HOST = "http://cmdb/api"
MOCK_AUTH_PRIV_KEY = "3432"


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


@patch('authentication.amqp.listeners.os.getenv', mock_os_getenv)
class TestOrgUserRoleListener(TestCase):
    def setUp(self):
        self.listener = OrgUserRoleListener(MOCK_RABBIT_HOST)

    @patch("authentication.amqp.listeners.kv")
    @patch("authentication.api.auth_methods.create_jwt_token")
    @patch("authentication.amqp.listeners.requests")
    @patch("authentication.api.auth_methods.requests")
    def test_handle_message_type_create_reg_state_pending_should_send_email(self, mock_gubn, mock_r, mock_jwt, mock_kv):
        mock_jwt.return_value = "123"
        random_id = str(uuid.uuid4())

        resp = Response()
        resp.status_code = 200
        resp.json = Mock()
        resp.json.return_value = {
            "user": {
                "identifier": str(uuid.uuid4()),
                "username": "admin@factioninc.com",
                "email": "admin@factioninc.com",
                "authmethod": "faction",
                "contactMethods": [],
                "defaultorg": {
                    "identifier": random_id,
                    "uri": "/api/general/users/" + random_id
                },
                "registrationstate": "pending"
            }
        }
        mock_r.get.return_value = resp
        mock_gubn.get_value = resp

        msg = {
            'identifier': 'dd936711-e0cd-4e7a-af6c-defd492b2862',
            'etag': '4784947f-6dd5-4332-a178-36a82332e4e1',
            'type': 'create'
        }

        mock_r.post = Mock()
        mock_kv.set = Mock()

        self.listener.handle_message(msg)

        uri_arg = mock_r.post.call_args[0][0]
        self.assertTrue(uri_arg.endswith("/notifier/email"))
        mock_kv.set.assert_called()

    @patch("authentication.amqp.listeners.kv")
    @patch("authentication.amqp.listeners.requests")
    def test_handle_message_type_create_reg_state_not_pending_should_not_send_email(self, mock_r, mock_kv):
        msg = {
            'identifier': 'dd936711-e0cd-4e7a-af6c-defd492b2862',
            'etag': '4784947f-6dd5-4332-a178-36a82332e4e1',
            'type': 'delete'
        }
        mock_r.post = Mock()
        mock_kv.set = Mock()

        self.listener.handle_message(msg)
        mock_r.post.assert_not_called()
        mock_kv.set.assert_not_called()

    @patch("authentication.amqp.listeners.requests")
    def test_handle_message_type_update(self, mock_r):
        msg = {
            'identifier': 'dd936711-e0cd-4e7a-af6c-defd492b2862',
            'etag': '4784947f-6dd5-4332-a178-36a82332e4e1',
            'type': 'update'
        }
        mock_r.get = Mock()
        mock_r.post = Mock()

        self.listener.handle_message(msg)
        mock_r.get.assert_not_called()
        mock_r.post.assert_not_called()

    @patch("authentication.amqp.listeners.requests")
    def test_handle_message_type_delete(self, mock_r):
        msg = {
            'identifier': 'dd936711-e0cd-4e7a-af6c-defd492b2862',
            'etag': '4784947f-6dd5-4332-a178-36a82332e4e1',
            'type': 'delete'
        }
        mock_r.get = Mock()
        mock_r.post = Mock()

        self.listener.handle_message(msg)
        mock_r.get.assert_not_called()
        mock_r.post.assert_not_called()
