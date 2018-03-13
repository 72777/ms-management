import random
from unittest import TestCase
from unittest.mock import patch, Mock

import jwt
import werkzeug.exceptions
from requests import Response

from authentication.blueprints.ns_oauth import GoogleOauthProviderAPI, GithubOauthProviderAPI, \
    GITHUB_OAUTH_AUTHORIZE_ENDPOINT, OauthAPI
from authentication.keyval import KeyValueError

MOCK_RABBIT_HOST = 'amqp://rabbit:5672'
MOCK_NOTIFIER_HOST = 'http://abc/notifier'
MOCK_CMDB_HOST = 'http://cmdb/api'
MOCK_AUTH_PRIV_KEY = '3432'
MOCK_OAUTH_GOOGLE_CLIENT_ID = 'mock_client_id'
MOCK_OAUTH_GOOGLE_CLIENT_SECRET = 'mock_client_secret'
MOCK_OAUTH_GITHUB_CLIENT_ID = 'mock_client_id'
MOCK_OAUTH_GITHUB_CLIENT_SECRET = 'mock_client_secret'
MOCK_OAUTH_REDIRECT_URI = 'mock_redirect_uri'


def mock_os_getenv(key, default=None):
    if key == 'RABBIT_HOST':
        return MOCK_RABBIT_HOST
    elif key == 'NOTIFIER_HOST':
        return MOCK_NOTIFIER_HOST
    elif key == 'CMDB_HOST':
        return MOCK_CMDB_HOST
    elif key == 'AUTH_PRIV_KEY':
        return MOCK_AUTH_PRIV_KEY
    elif key == 'OAUTH_GOOGLE_CLIENT_ID':
        return MOCK_OAUTH_GOOGLE_CLIENT_ID
    elif key == 'OAUTH_GOOGLE_CLIENT_SECRET':
        return MOCK_OAUTH_GOOGLE_CLIENT_SECRET
    elif key == 'OAUTH_GITHUB_CLIENT_ID':
        return MOCK_OAUTH_GOOGLE_CLIENT_ID
    elif key == 'OAUTH_GITHUB_CLIENT_SECRET':
        return MOCK_OAUTH_GITHUB_CLIENT_SECRET
    elif key == 'OAUTH_REDIRECT_URI':
        return MOCK_OAUTH_REDIRECT_URI
    else:
        return default


def mock_create_token(creds, key, expire=None):
    return 'sometoken'


@patch('authentication.blueprints.ns_oauth.os.getenv', mock_os_getenv)
class TestGithubOauthProviderAPI(TestCase):
    @patch('authentication.blueprints.ns_oauth.kv')
    def test_build_oauth2_url(self, mock_kv):
        mock_kv.set = Mock(return_value=None)

        url = GithubOauthProviderAPI.build_oauth2_url()
        mock_kv.set.assert_called()

        self.assertTrue(GITHUB_OAUTH_AUTHORIZE_ENDPOINT in url)
        self.assertTrue('scope=user:email' in url)
        self.assertTrue('state=' in url)
        self.assertTrue('redirect_uri=' in url)
        self.assertTrue('client_id=' in url)

    def test_authenticate_not_ok_response(self):
        self.assertRaises(werkzeug.exceptions.Unauthorized, GithubOauthProviderAPI.authenticate, 'some_auth_code')

    @patch('authentication.blueprints.ns_oauth.requests')
    def test_authenticate_ok_response(self, mock_r):
        mock_response = Response()
        mock_response.status_code = 200
        expected_tokens = {
            'access_token': 'some_access_token',
        }
        mock_response.json = Mock(return_value=expected_tokens)
        mock_r.post = Mock(return_value=mock_response)

        tokens = GithubOauthProviderAPI.authenticate('some_valid_auth_code')
        self.assertEqual(tokens, expected_tokens)

    @patch('authentication.blueprints.ns_oauth.requests')
    def test_retrieve_user_email_not_ok_response(self, mock_r):
        mock_response = Response()
        mock_response.status_code = 400
        mock_r.get = Mock(return_value=mock_response)

        self.assertRaises(werkzeug.exceptions.Unauthorized, GithubOauthProviderAPI.retrieve_user_email, {
            'access_token': 'some_access_token'
        })

    @patch('authentication.blueprints.ns_oauth.requests')
    def test_retrieve_user_email_not_list_response(self, mock_r):
        mock_response = Response()
        mock_response.status_code = 200
        mock_response.json = Mock(return_value={})
        mock_r.get = Mock(return_value=mock_response)

        self.assertRaises(werkzeug.exceptions.Unauthorized, GithubOauthProviderAPI.retrieve_user_email, {
            'access_token': 'some_access_token'
        })

    @patch('authentication.blueprints.ns_oauth.requests')
    def test_retrieve_user_email_not_list_response(self, mock_r):
        mock_response = Response()
        mock_response.status_code = 200
        mock_response.json = Mock(return_value={})
        mock_r.get = Mock(return_value=mock_response)

        self.assertRaises(werkzeug.exceptions.Unauthorized, GithubOauthProviderAPI.retrieve_user_email, {
            'access_token': 'some_access_token'
        })

    @patch('authentication.blueprints.ns_oauth.requests')
    def test_retrieve_user_email_empty_list_response(self, mock_r):
        mock_response = Response()
        mock_response.status_code = 200
        mock_response.json = Mock(return_value=[])
        mock_r.get = Mock(return_value=mock_response)

        self.assertRaises(werkzeug.exceptions.Unauthorized, GithubOauthProviderAPI.retrieve_user_email, {
            'access_token': 'some_access_token'
        })

    @patch('authentication.blueprints.ns_oauth.requests')
    def test_retrieve_user_email_no_primary_and_verified_email(self, mock_r):
        mock_response = Response()
        mock_response.status_code = 200
        mock_response.json = Mock(return_value=[
            {
                'primary': False,
                'verified': True,
                'email': 'myemail@gmail.com'
            }
        ])
        mock_r.get = Mock(return_value=mock_response)

        self.assertRaises(werkzeug.exceptions.Unauthorized, GithubOauthProviderAPI.retrieve_user_email, {
            'access_token': 'some_access_token'
        })

    @patch('authentication.blueprints.ns_oauth.requests')
    def test_retrieve_user_email_success(self, mock_r):
        mock_response = Response()
        expected_email = 'abc@gmail.com'
        mock_response.json = Mock(return_value=[{
            'primary': True,
            'verified': True,
            'email': expected_email
        }])

        mock_response.status_code = 200
        mock_r.get = Mock(return_value=mock_response)

        email = GithubOauthProviderAPI.retrieve_user_email({
            'access_token': 'some_access_token'
        })
        self.assertEqual(email, expected_email)


@patch('authentication.blueprints.ns_oauth.os.getenv', mock_os_getenv)
class TestGoogleOauthProviderAPI(TestCase):
    @patch('authentication.blueprints.ns_oauth.requests')
    @patch('authentication.blueprints.ns_oauth.kv')
    def test_build_oauth2_url(self, mock_kv, mock_r):
        mock_endpoint = {'authorization_endpoint': 'google_auth_endpoint'}
        mock_response = Response()
        mock_response.json = Mock(return_value=mock_endpoint)
        mock_r.get = Mock(return_value=mock_response)
        mock_kv.set = Mock(return_value=None)

        url = GoogleOauthProviderAPI.build_oauth2_url()
        mock_kv.set.assert_called()

        self.assertTrue(mock_endpoint['authorization_endpoint'] in url)
        self.assertTrue('scope=openid email' in url)
        self.assertTrue('nonce=' in url)
        self.assertTrue('state=' in url)
        self.assertTrue('redirect_uri=' in url)
        self.assertTrue('response_type=code' in url)
        self.assertTrue('client_id=' in url)

    def test_authenticate_not_ok_response(self):
        self.assertRaises(werkzeug.exceptions.Unauthorized, GoogleOauthProviderAPI.authenticate, 'some_auth_code')

    @patch('authentication.blueprints.ns_oauth.requests')
    def test_authenticate_ok_response(self, mock_r):
        mock_response = Response()
        mock_response.status_code = 200
        expected_tokens = {
            'access_token': 'some_access_token',
            'id_token': 'some_id_token'
        }
        mock_response.json = Mock(return_value=expected_tokens)

        mock_endpoint = {'token_endpoint': 'google_token_endpoint'}
        mock_get_response = Response()
        mock_get_response.status_code = 200
        mock_get_response.json = Mock(return_value=mock_endpoint)

        mock_r.get = Mock(return_value=mock_get_response)
        mock_r.post = Mock(return_value=mock_response)

        tokens = GoogleOauthProviderAPI.authenticate('some_valid_auth_code')
        self.assertEqual(tokens, expected_tokens)

    @patch('authentication.blueprints.ns_oauth.jwt.get_unverified_header')
    def test_retrieve_user_email_invalid_token_header(self, mock_jwt_get_unverified_header):
        mock_jwt_get_unverified_header.side_effect = jwt.exceptions.InvalidTokenError

        self.assertRaises(werkzeug.exceptions.Unauthorized, GoogleOauthProviderAPI.retrieve_user_email, {
            'id_token': 'some_id_token',
            'access_token': 'some_access_token'
        })

    @patch('authentication.blueprints.ns_oauth.requests')
    @patch('authentication.blueprints.ns_oauth.jwt.get_unverified_header')
    @patch('authentication.blueprints.ns_oauth.jwt.decode')
    def test_retrieve_user_email_invalid_token(self, mock_decode, mock_jwt_get_unverified_header, mock_r):
        mock_jwt_get_unverified_header.return_value = {
            'kid': '9c37bf73343adb93920a7ae80260b0e57684551e'
        }
        mock_endpoint = {'jwks_uri': 'google_jwks_uri_endpoint'}
        mock_keys_endpoints = {
            'keys': [
                {
                    'kty': 'RSA',
                    'alg': 'RS256',
                    'use': 'sig',
                    'kid': '9c37bf73343adb93920a7ae80260b0e57684551e',
                    'n': 'rZ_JRz8H-Y5tD1bykrqicWgtGmlX_nGFl7NM_xq_P3vJwSYYeOVPXfrugYIbKZETPe3T3eBrXibgGkv4PdGB5j3jrEzqENkqZd3xSeTCrfv1SBLptzid7Y4dyeRyJGY0_GfrRb7yCMkeq-87KpwA6hww0aAQx5jc9tZBdv9XvS7efWhJtoeBrHhSOUMcaujBZst2V9_owud1i-WfOemSKZIXTkobENGLTbTOahZ0YU8jazq1jptWiAsyGlFIwOQR8e6dM38M9AgznGN8vggrS_NnW9RudicWQey19uOcUiMRCbEA2d6lfv0YGkQlOaAdQrpyi4fWieT1qR5BvVjHfQ',
                    'e': 'AQAB'
                },
                {
                    'kty': 'RSA',
                    'alg': 'RS256',
                    'use': 'sig',
                    'kid': 'bc4d3afc492e48bf0dbc194a31bdddc7d7a2a941',
                    'n': '0l505WsauSD0UfwmtB1aLt8NlWIgf3ikzW4aXOWrceypUmZ_PD2cbiKJeXWU8ZXbS-6_ASaAEuUA-a2bFcKByYJ9CcPcODY0iOtK64J3qhQaoqTvyVlrH7vT9palxGtFs4O87JHNnLgT7HfJP6InIS7ARvb_jQem5uNViHciCpnQgqEY6zM36oVVDPWlu3P-iqI0Qkohb92JkvICLGZrW1ouwuMSBDIwVmvELW3gEw4XoEMVTVDsGqwFkmR3pKGD_eg-9PgpHZHWH4Wp2orUEWyY-tMGe-96P9OmMgmunJxRUV2VHJYb5JrKwZl8QTvXwGPzX7cOx69G8yYLgkPi6Q',
                    'e': 'AQAB'
                },
                {
                    'kty': 'RSA',
                    'alg': 'RS256',
                    'use': 'sig',
                    'kid': '26c018b233fe2eef47fedbbdd9398170fc9b29d8',
                    'n': '5miiKafEc9VfN6Io1H6_qzPYhHFUhh9_OIA3JQ7hlvv3ydcBFbZwuMJGFWZXTh-C5F_0mDsFo6H524tlGUAeagEZV7gnEou1t4jJ78Gdi7qQXcJtOHJRK2gEz_RREICxCil1ybT7pdc_PgrhHr32zszA4hyXVL6nts6APfTXK6oSlfvbpU5prGyLOL5KwAp-ALz0lJmoh0oj9g3QgGAZkuoAHj64G49ws1k54748cj9Y-YwcNV00zwvdH_XU0xKOiksC_O_FArKc7bhaiC57FkPJ9NFOcZhNZ8PknHXVEENSxT6YFgVTNDDBenZDvAX2DblgZjc6n_GyZZq5AIl3uQ',
                    'e': 'AQAB'
                },
                {
                    'kty': 'RSA',
                    'alg': 'RS256',
                    'use': 'sig',
                    'kid': 'ba4ded7f5a92429f233561a36ff613ed38762c3d',
                    'n': 'xy7mPuuYEsn9on4GH7gfoHDQnCabyGa3RgEhL8P7GejHUZswyaVRUmCcTm47Yf6w3dlCVVaO7UBP3kpjn3qjbSzMtKklVvZ51wX7OinMY1TGRKmZAK6S0I5n7WTyaXwT_QDVh1JEsK7Smi7wGfOiKlVlOd_DPdPhIgBV7qG55amLyurKf3WI2yEthK_BgLZezbv3hKDdyr56qi27BobLf263IRl2BepkVDcMnFWuNH4UVr2AqyoyjXbAmw7iNAz6LN0955r2qacgT-BfRbhNw9AkdJ_D1EFKnuwvuVIgZT61Hax2yIznOnnoP1pwZYtVoW2WM9DYIa0St8ZT7SOH9Q',
                    'e': 'AQAB'
                }
            ]
        }
        mock_response = Response()
        mock_response.json = Mock(return_value=mock_endpoint)
        mock_jwk_response = Response()
        mock_jwk_response.json = Mock(return_value=mock_keys_endpoints)

        mock_decode.side_effect = jwt.exceptions.InvalidTokenError
        mock_r.get = Mock(side_effect=[mock_response, mock_jwk_response])

        self.assertRaises(werkzeug.exceptions.Unauthorized, GoogleOauthProviderAPI.retrieve_user_email, {
            'id_token': 'some_id_token',
            'access_token': 'some_access_token'
        })

    @patch('authentication.blueprints.ns_oauth.requests')
    @patch('authentication.blueprints.ns_oauth.jwt.get_unverified_header')
    @patch('authentication.blueprints.ns_oauth.jwt.decode')
    def test_retrieve_user_email_invalid_aud(self, mock_decode, mock_jwt_get_unverified_header, mock_r):
        mock_jwt_get_unverified_header.return_value = {
            'kid': '9c37bf73343adb93920a7ae80260b0e57684551e'
        }
        mock_endpoint = {'jwks_uri': 'google_jwks_uri_endpoint'}
        mock_keys_endpoints = {
            'keys': [
                {
                    'kty': 'RSA',
                    'alg': 'RS256',
                    'use': 'sig',
                    'kid': '9c37bf73343adb93920a7ae80260b0e57684551e',
                    'n': 'rZ_JRz8H-Y5tD1bykrqicWgtGmlX_nGFl7NM_xq_P3vJwSYYeOVPXfrugYIbKZETPe3T3eBrXibgGkv4PdGB5j3jrEzqENkqZd3xSeTCrfv1SBLptzid7Y4dyeRyJGY0_GfrRb7yCMkeq-87KpwA6hww0aAQx5jc9tZBdv9XvS7efWhJtoeBrHhSOUMcaujBZst2V9_owud1i-WfOemSKZIXTkobENGLTbTOahZ0YU8jazq1jptWiAsyGlFIwOQR8e6dM38M9AgznGN8vggrS_NnW9RudicWQey19uOcUiMRCbEA2d6lfv0YGkQlOaAdQrpyi4fWieT1qR5BvVjHfQ',
                    'e': 'AQAB'
                },
                {
                    'kty': 'RSA',
                    'alg': 'RS256',
                    'use': 'sig',
                    'kid': 'bc4d3afc492e48bf0dbc194a31bdddc7d7a2a941',
                    'n': '0l505WsauSD0UfwmtB1aLt8NlWIgf3ikzW4aXOWrceypUmZ_PD2cbiKJeXWU8ZXbS-6_ASaAEuUA-a2bFcKByYJ9CcPcODY0iOtK64J3qhQaoqTvyVlrH7vT9palxGtFs4O87JHNnLgT7HfJP6InIS7ARvb_jQem5uNViHciCpnQgqEY6zM36oVVDPWlu3P-iqI0Qkohb92JkvICLGZrW1ouwuMSBDIwVmvELW3gEw4XoEMVTVDsGqwFkmR3pKGD_eg-9PgpHZHWH4Wp2orUEWyY-tMGe-96P9OmMgmunJxRUV2VHJYb5JrKwZl8QTvXwGPzX7cOx69G8yYLgkPi6Q',
                    'e': 'AQAB'
                },
                {
                    'kty': 'RSA',
                    'alg': 'RS256',
                    'use': 'sig',
                    'kid': '26c018b233fe2eef47fedbbdd9398170fc9b29d8',
                    'n': '5miiKafEc9VfN6Io1H6_qzPYhHFUhh9_OIA3JQ7hlvv3ydcBFbZwuMJGFWZXTh-C5F_0mDsFo6H524tlGUAeagEZV7gnEou1t4jJ78Gdi7qQXcJtOHJRK2gEz_RREICxCil1ybT7pdc_PgrhHr32zszA4hyXVL6nts6APfTXK6oSlfvbpU5prGyLOL5KwAp-ALz0lJmoh0oj9g3QgGAZkuoAHj64G49ws1k54748cj9Y-YwcNV00zwvdH_XU0xKOiksC_O_FArKc7bhaiC57FkPJ9NFOcZhNZ8PknHXVEENSxT6YFgVTNDDBenZDvAX2DblgZjc6n_GyZZq5AIl3uQ',
                    'e': 'AQAB'
                },
                {
                    'kty': 'RSA',
                    'alg': 'RS256',
                    'use': 'sig',
                    'kid': 'ba4ded7f5a92429f233561a36ff613ed38762c3d',
                    'n': 'xy7mPuuYEsn9on4GH7gfoHDQnCabyGa3RgEhL8P7GejHUZswyaVRUmCcTm47Yf6w3dlCVVaO7UBP3kpjn3qjbSzMtKklVvZ51wX7OinMY1TGRKmZAK6S0I5n7WTyaXwT_QDVh1JEsK7Smi7wGfOiKlVlOd_DPdPhIgBV7qG55amLyurKf3WI2yEthK_BgLZezbv3hKDdyr56qi27BobLf263IRl2BepkVDcMnFWuNH4UVr2AqyoyjXbAmw7iNAz6LN0955r2qacgT-BfRbhNw9AkdJ_D1EFKnuwvuVIgZT61Hax2yIznOnnoP1pwZYtVoW2WM9DYIa0St8ZT7SOH9Q',
                    'e': 'AQAB'
                }
            ]
        }
        mock_response = Response()
        mock_response.json = Mock(return_value=mock_endpoint)
        mock_jwk_response = Response()
        mock_jwk_response.json = Mock(return_value=mock_keys_endpoints)

        mock_decode.return_value = {
            'aud': 'not_equal_to_client_id',
            'iss': 'https://accounts.google.com'
        }
        mock_r.get = Mock(side_effect=[mock_response, mock_jwk_response])

        self.assertRaises(werkzeug.exceptions.Unauthorized, GoogleOauthProviderAPI.retrieve_user_email, {
            'id_token': 'some_id_token',
            'access_token': 'some_access_token'
        })

    @patch('authentication.blueprints.ns_oauth.requests')
    @patch('authentication.blueprints.ns_oauth.jwt.get_unverified_header')
    @patch('authentication.blueprints.ns_oauth.jwt.decode')
    def test_retrieve_user_email_invalid_iss(self, mock_decode, mock_jwt_get_unverified_header, mock_r):
        mock_jwt_get_unverified_header.return_value = {
            'kid': '9c37bf73343adb93920a7ae80260b0e57684551e'
        }
        mock_endpoint = {'jwks_uri': 'google_jwks_uri_endpoint'}
        mock_keys_endpoints = {
            'keys': [
                {
                    'kty': 'RSA',
                    'alg': 'RS256',
                    'use': 'sig',
                    'kid': '9c37bf73343adb93920a7ae80260b0e57684551e',
                    'n': 'rZ_JRz8H-Y5tD1bykrqicWgtGmlX_nGFl7NM_xq_P3vJwSYYeOVPXfrugYIbKZETPe3T3eBrXibgGkv4PdGB5j3jrEzqENkqZd3xSeTCrfv1SBLptzid7Y4dyeRyJGY0_GfrRb7yCMkeq-87KpwA6hww0aAQx5jc9tZBdv9XvS7efWhJtoeBrHhSOUMcaujBZst2V9_owud1i-WfOemSKZIXTkobENGLTbTOahZ0YU8jazq1jptWiAsyGlFIwOQR8e6dM38M9AgznGN8vggrS_NnW9RudicWQey19uOcUiMRCbEA2d6lfv0YGkQlOaAdQrpyi4fWieT1qR5BvVjHfQ',
                    'e': 'AQAB'
                },
                {
                    'kty': 'RSA',
                    'alg': 'RS256',
                    'use': 'sig',
                    'kid': 'bc4d3afc492e48bf0dbc194a31bdddc7d7a2a941',
                    'n': '0l505WsauSD0UfwmtB1aLt8NlWIgf3ikzW4aXOWrceypUmZ_PD2cbiKJeXWU8ZXbS-6_ASaAEuUA-a2bFcKByYJ9CcPcODY0iOtK64J3qhQaoqTvyVlrH7vT9palxGtFs4O87JHNnLgT7HfJP6InIS7ARvb_jQem5uNViHciCpnQgqEY6zM36oVVDPWlu3P-iqI0Qkohb92JkvICLGZrW1ouwuMSBDIwVmvELW3gEw4XoEMVTVDsGqwFkmR3pKGD_eg-9PgpHZHWH4Wp2orUEWyY-tMGe-96P9OmMgmunJxRUV2VHJYb5JrKwZl8QTvXwGPzX7cOx69G8yYLgkPi6Q',
                    'e': 'AQAB'
                },
                {
                    'kty': 'RSA',
                    'alg': 'RS256',
                    'use': 'sig',
                    'kid': '26c018b233fe2eef47fedbbdd9398170fc9b29d8',
                    'n': '5miiKafEc9VfN6Io1H6_qzPYhHFUhh9_OIA3JQ7hlvv3ydcBFbZwuMJGFWZXTh-C5F_0mDsFo6H524tlGUAeagEZV7gnEou1t4jJ78Gdi7qQXcJtOHJRK2gEz_RREICxCil1ybT7pdc_PgrhHr32zszA4hyXVL6nts6APfTXK6oSlfvbpU5prGyLOL5KwAp-ALz0lJmoh0oj9g3QgGAZkuoAHj64G49ws1k54748cj9Y-YwcNV00zwvdH_XU0xKOiksC_O_FArKc7bhaiC57FkPJ9NFOcZhNZ8PknHXVEENSxT6YFgVTNDDBenZDvAX2DblgZjc6n_GyZZq5AIl3uQ',
                    'e': 'AQAB'
                },
                {
                    'kty': 'RSA',
                    'alg': 'RS256',
                    'use': 'sig',
                    'kid': 'ba4ded7f5a92429f233561a36ff613ed38762c3d',
                    'n': 'xy7mPuuYEsn9on4GH7gfoHDQnCabyGa3RgEhL8P7GejHUZswyaVRUmCcTm47Yf6w3dlCVVaO7UBP3kpjn3qjbSzMtKklVvZ51wX7OinMY1TGRKmZAK6S0I5n7WTyaXwT_QDVh1JEsK7Smi7wGfOiKlVlOd_DPdPhIgBV7qG55amLyurKf3WI2yEthK_BgLZezbv3hKDdyr56qi27BobLf263IRl2BepkVDcMnFWuNH4UVr2AqyoyjXbAmw7iNAz6LN0955r2qacgT-BfRbhNw9AkdJ_D1EFKnuwvuVIgZT61Hax2yIznOnnoP1pwZYtVoW2WM9DYIa0St8ZT7SOH9Q',
                    'e': 'AQAB'
                }
            ]
        }
        mock_response = Response()
        mock_response.json = Mock(return_value=mock_endpoint)
        mock_jwk_response = Response()
        mock_jwk_response.json = Mock(return_value=mock_keys_endpoints)

        mock_decode.return_value = {
            'aud': MOCK_OAUTH_GOOGLE_CLIENT_ID,
            'iss': 'not_equal_tohttps://accounts.google.com'
        }
        mock_r.get = Mock(side_effect=[mock_response, mock_jwk_response])

        self.assertRaises(werkzeug.exceptions.Unauthorized, GoogleOauthProviderAPI.retrieve_user_email, {
            'id_token': 'some_id_token',
            'access_token': 'some_access_token'
        })

    @patch('authentication.blueprints.ns_oauth.requests')
    @patch('authentication.blueprints.ns_oauth.jwt.get_unverified_header')
    @patch('authentication.blueprints.ns_oauth.jwt.decode')
    def test_retrieve_user_email_success(self, mock_decode, mock_jwt_get_unverified_header, mock_r):
        mock_jwt_get_unverified_header.return_value = {
            'kid': '9c37bf73343adb93920a7ae80260b0e57684551e'
        }
        mock_endpoint = {'jwks_uri': 'google_jwks_uri_endpoint'}
        mock_keys_endpoints = {
            'keys': [
                {
                    'kty': 'RSA',
                    'alg': 'RS256',
                    'use': 'sig',
                    'kid': '9c37bf73343adb93920a7ae80260b0e57684551e',
                    'n': 'rZ_JRz8H-Y5tD1bykrqicWgtGmlX_nGFl7NM_xq_P3vJwSYYeOVPXfrugYIbKZETPe3T3eBrXibgGkv4PdGB5j3jrEzqENkqZd3xSeTCrfv1SBLptzid7Y4dyeRyJGY0_GfrRb7yCMkeq-87KpwA6hww0aAQx5jc9tZBdv9XvS7efWhJtoeBrHhSOUMcaujBZst2V9_owud1i-WfOemSKZIXTkobENGLTbTOahZ0YU8jazq1jptWiAsyGlFIwOQR8e6dM38M9AgznGN8vggrS_NnW9RudicWQey19uOcUiMRCbEA2d6lfv0YGkQlOaAdQrpyi4fWieT1qR5BvVjHfQ',
                    'e': 'AQAB'
                },
                {
                    'kty': 'RSA',
                    'alg': 'RS256',
                    'use': 'sig',
                    'kid': 'bc4d3afc492e48bf0dbc194a31bdddc7d7a2a941',
                    'n': '0l505WsauSD0UfwmtB1aLt8NlWIgf3ikzW4aXOWrceypUmZ_PD2cbiKJeXWU8ZXbS-6_ASaAEuUA-a2bFcKByYJ9CcPcODY0iOtK64J3qhQaoqTvyVlrH7vT9palxGtFs4O87JHNnLgT7HfJP6InIS7ARvb_jQem5uNViHciCpnQgqEY6zM36oVVDPWlu3P-iqI0Qkohb92JkvICLGZrW1ouwuMSBDIwVmvELW3gEw4XoEMVTVDsGqwFkmR3pKGD_eg-9PgpHZHWH4Wp2orUEWyY-tMGe-96P9OmMgmunJxRUV2VHJYb5JrKwZl8QTvXwGPzX7cOx69G8yYLgkPi6Q',
                    'e': 'AQAB'
                },
                {
                    'kty': 'RSA',
                    'alg': 'RS256',
                    'use': 'sig',
                    'kid': '26c018b233fe2eef47fedbbdd9398170fc9b29d8',
                    'n': '5miiKafEc9VfN6Io1H6_qzPYhHFUhh9_OIA3JQ7hlvv3ydcBFbZwuMJGFWZXTh-C5F_0mDsFo6H524tlGUAeagEZV7gnEou1t4jJ78Gdi7qQXcJtOHJRK2gEz_RREICxCil1ybT7pdc_PgrhHr32zszA4hyXVL6nts6APfTXK6oSlfvbpU5prGyLOL5KwAp-ALz0lJmoh0oj9g3QgGAZkuoAHj64G49ws1k54748cj9Y-YwcNV00zwvdH_XU0xKOiksC_O_FArKc7bhaiC57FkPJ9NFOcZhNZ8PknHXVEENSxT6YFgVTNDDBenZDvAX2DblgZjc6n_GyZZq5AIl3uQ',
                    'e': 'AQAB'
                },
                {
                    'kty': 'RSA',
                    'alg': 'RS256',
                    'use': 'sig',
                    'kid': 'ba4ded7f5a92429f233561a36ff613ed38762c3d',
                    'n': 'xy7mPuuYEsn9on4GH7gfoHDQnCabyGa3RgEhL8P7GejHUZswyaVRUmCcTm47Yf6w3dlCVVaO7UBP3kpjn3qjbSzMtKklVvZ51wX7OinMY1TGRKmZAK6S0I5n7WTyaXwT_QDVh1JEsK7Smi7wGfOiKlVlOd_DPdPhIgBV7qG55amLyurKf3WI2yEthK_BgLZezbv3hKDdyr56qi27BobLf263IRl2BepkVDcMnFWuNH4UVr2AqyoyjXbAmw7iNAz6LN0955r2qacgT-BfRbhNw9AkdJ_D1EFKnuwvuVIgZT61Hax2yIznOnnoP1pwZYtVoW2WM9DYIa0St8ZT7SOH9Q',
                    'e': 'AQAB'
                }
            ]
        }
        mock_response = Response()
        mock_response.json = Mock(return_value=mock_endpoint)
        mock_jwk_response = Response()
        mock_jwk_response.json = Mock(return_value=mock_keys_endpoints)

        expected_email = 'abc@gmail.com'
        mock_decode.return_value = {
            'aud': MOCK_OAUTH_GOOGLE_CLIENT_ID,
            'iss': 'https://accounts.google.com',
            'email': expected_email
        }
        mock_r.get = Mock(side_effect=[mock_response, mock_jwk_response])

        email = GoogleOauthProviderAPI.retrieve_user_email({
            'id_token': 'some_id_token',
            'access_token': 'some_access_token'
        })
        self.assertEqual(email, expected_email)


@patch('authentication.blueprints.ns_oauth.os.getenv', mock_os_getenv)
@patch('authentication.blueprints.ns_oauth.create_jwt_token', mock_create_token)
class TestOauthAPI(TestCase):
    @patch('authentication.blueprints.ns_oauth.kv')
    def test_validate_state_does_not_exist_in_keystore(self, mock_kv):
        mock_kv.get_dict = Mock(side_effect=KeyValueError('', ''))
        data = {
            'state': 'some_state'
        }
        self.assertRaises(werkzeug.exceptions.Unauthorized, OauthAPI.validate_state, data)

    @patch('authentication.blueprints.ns_oauth.kv')
    def test_validate_state_success(self, mock_kv):
        expected_state = {'oauth_provider': random.choice(['google', 'github'])}
        mock_kv.get_dict = Mock(return_value=expected_state)
        mock_kv.delete = Mock()

        data = {
            'state': 'somestatevalue'
        }

        state = OauthAPI.validate_state(data)
        self.assertEqual(state, expected_state)

        mock_kv.delete.assert_called_with(data['state'])

    def test_determine_provider_google(self):
        state = {
            'oauth_provider': 'google'
        }
        provider = OauthAPI.determine_provider(state)
        self.assertTrue(isinstance(provider, GoogleOauthProviderAPI))

    def test_determine_provider_github(self):
        state = {
            'oauth_provider': 'github'
        }
        provider = OauthAPI.determine_provider(state)
        self.assertTrue(isinstance(provider, GithubOauthProviderAPI))

    def test_determine_provider_other(self):
        state = {
            'oauth_provider': 'some_unsupported_provider'
        }
        provider = OauthAPI.determine_provider(state)
        self.assertIsNone(provider)

    @patch('authentication.blueprints.ns_oauth.requests')
    def test_validate_oauth_user_cmdb_not_ok_response(self, mock_r):
        mock_get_response = Response()
        mock_get_response.status_code = 400
        mock_r.get = Mock(return_value=mock_get_response)

        mock_google_oauth_provider = GoogleOauthProviderAPI()
        mock_google_oauth_provider.authenticate = Mock(return_value={
            'id_token': 'some_id_token',
            'access_token': 'some_access_token'
        })
        mock_google_oauth_provider.retrieve_user_email = Mock(return_value='abc@gmail.com')

        mock_github_oauth_provider = GithubOauthProviderAPI()
        mock_github_oauth_provider.authenticate = Mock(return_value={
            'access_token': 'some_access_token'
        })
        mock_github_oauth_provider.retrieve_user_email = Mock(return_value='abc@gmail.com')

        data = {
            'authorization_code': 'some_code',
            'state': 'some_state'
        }
        self.assertRaises(werkzeug.exceptions.InternalServerError,
                          OauthAPI.validate_oauth_user,
                          random.choice([mock_google_oauth_provider, mock_github_oauth_provider]),
                          data)

    @patch('authentication.blueprints.ns_oauth.requests')
    def test_validate_oauth_user_cmdb_empty_list(self, mock_r):
        mock_get_response = Response()
        mock_get_response.status_code = 200
        mock_get_response.json = Mock(return_value=[])
        mock_r.get = Mock(return_value=mock_get_response)

        mock_google_oauth_provider = GoogleOauthProviderAPI()
        mock_google_oauth_provider.authenticate = Mock(return_value={
            'id_token': 'some_id_token',
            'access_token': 'some_access_token'
        })
        mock_google_oauth_provider.retrieve_user_email = Mock(return_value='abc@gmail.com')

        mock_github_oauth_provider = GithubOauthProviderAPI()
        mock_github_oauth_provider.authenticate = Mock(return_value={
            'access_token': 'some_access_token'
        })
        mock_github_oauth_provider.retrieve_user_email = Mock(return_value='abc@gmail.com')

        data = {
            'authorization_code': 'some_code',
            'state': 'some_state'
        }
        self.assertRaises(werkzeug.exceptions.Unauthorized,
                          OauthAPI.validate_oauth_user,
                          random.choice([mock_google_oauth_provider, mock_github_oauth_provider]),
                          data)

    @patch('authentication.blueprints.ns_oauth.requests')
    def test_validate_oauth_user_cmdb_user_found_orguserrole_call_failed(self, mock_r):
        mock_get_user_response = Response()
        mock_get_user_response.status_code = 200
        mock_get_orguserrole_response = Response()
        mock_get_orguserrole_response.status_code = 400
        mock_get_user_response.json = Mock(return_value=[{
            'identifier': 'user_id',
            'defaultorg': {
                'identifier': 'org_id'
            }
        }])
        mock_r.get = Mock(side_effect=[mock_get_user_response, mock_get_orguserrole_response])

        mock_google_oauth_provider = GoogleOauthProviderAPI()
        mock_google_oauth_provider.authenticate = Mock(return_value={
            'id_token': 'some_id_token',
            'access_token': 'some_access_token'
        })
        mock_google_oauth_provider.retrieve_user_email = Mock(return_value='abc@gmail.com')

        mock_github_oauth_provider = GithubOauthProviderAPI()
        mock_github_oauth_provider.authenticate = Mock(return_value={
            'access_token': 'some_access_token'
        })
        mock_github_oauth_provider.retrieve_user_email = Mock(return_value='abc@gmail.com')

        data = {
            'authorization_code': 'some_code',
            'state': 'some_state'
        }
        self.assertRaises(werkzeug.exceptions.InternalServerError,
                          OauthAPI.validate_oauth_user,
                          random.choice([mock_google_oauth_provider, mock_github_oauth_provider]),
                          data)

    @patch('authentication.blueprints.ns_oauth.requests')
    def test_validate_oauth_user_cmdb_put_user_failed(self, mock_r):
        mock_get_user_response = Response()
        mock_get_user_response.status_code = 200
        mock_get_user_response.json = Mock(return_value=[{
            'identifier': 'user_id',
            'contactmethods': [],
            'registrationstate': 'pending',
            'tags': None,
            'defaultorg': {
                'identifier': 'org_id'
            }
        }])

        expected_roles = [{
            'identifier': 'orguserrole_id',
            'role': {
                'identifier': 'role_id',
                'name': 'Faction Admin'
            }
        }]
        mock_get_orguserrole_response = Response()
        mock_get_orguserrole_response.status_code = 200
        mock_get_orguserrole_response.json = Mock(return_value=expected_roles)

        mock_put_user_response = Response()
        mock_put_user_response.status_code = 400
        mock_r.get = Mock(side_effect=[mock_get_user_response, mock_get_orguserrole_response])
        mock_r.put = Mock(return_value=mock_put_user_response)

        mock_google_oauth_provider = GoogleOauthProviderAPI()
        mock_google_oauth_provider.authenticate = Mock(return_value={
            'id_token': 'some_id_token',
            'access_token': 'some_access_token'
        })
        mock_google_oauth_provider.retrieve_user_email = Mock(return_value='abc@gmail.com')

        mock_github_oauth_provider = GithubOauthProviderAPI()
        mock_github_oauth_provider.authenticate = Mock(return_value={
            'access_token': 'some_access_token'
        })
        mock_github_oauth_provider.retrieve_user_email = Mock(return_value='abc@gmail.com')

        data = {
            'authorization_code': 'some_code',
            'state': 'some_state'
        }
        self.assertRaises(werkzeug.exceptions.InternalServerError,
                          OauthAPI.validate_oauth_user,
                          random.choice([mock_google_oauth_provider, mock_github_oauth_provider]),
                          data)

    @patch('authentication.blueprints.ns_oauth.requests')
    def test_validate_oauth_user_success(self, mock_r):
        mock_get_user_response = Response()
        mock_get_user_response.status_code = 200
        mock_get_user_response.json = Mock(return_value=[{
            'identifier': 'user_id',
            'contactmethods': [],
            'registrationstate': 'pending',
            'tags': None,
            'defaultorg': {
                'identifier': 'org_id'
            }
        }])

        expected_roles = [{
            'identifier': 'orguserrole_id',
            'role': {
                'identifier': 'role_id',
                'name': 'Faction Admin'
            }
        }]
        mock_get_orguserrole_response = Response()
        mock_get_orguserrole_response.status_code = 200
        mock_get_orguserrole_response.json = Mock(return_value=expected_roles)

        expected_updated_user = {
            'identifier': 'user_id',
            'contactmethods': [],
            'registrationstate': 'registered',
            'tags': None,
            'defaultorg': {
                'identifier': 'org_id'
            }
        }
        mock_put_user_response = Response()
        mock_put_user_response.status_code = 200
        mock_put_user_response.json = Mock(return_value=expected_updated_user)
        mock_r.get = Mock(side_effect=[mock_get_user_response, mock_get_orguserrole_response])
        mock_r.put = Mock(return_value=mock_put_user_response)

        mock_google_oauth_provider = GoogleOauthProviderAPI()
        mock_google_oauth_provider.authenticate = Mock(return_value={
            'id_token': 'some_id_token',
            'access_token': 'some_access_token'
        })
        mock_google_oauth_provider.retrieve_user_email = Mock(return_value='abc@gmail.com')

        mock_github_oauth_provider = GithubOauthProviderAPI()
        mock_github_oauth_provider.authenticate = Mock(return_value={
            'access_token': 'some_access_token'
        })
        mock_github_oauth_provider.retrieve_user_email = Mock(return_value='abc@gmail.com')

        data = {
            'authorization_code': 'some_code',
            'state': 'some_state'
        }
        updated_user, roles = OauthAPI.validate_oauth_user(
            random.choice([mock_google_oauth_provider, mock_github_oauth_provider]), data)
        self.assertEqual(updated_user, expected_updated_user)
        self.assertEqual(roles, [expected_roles[0]['role']])
