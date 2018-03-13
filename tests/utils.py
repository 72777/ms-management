import os
import unittest

import jwt

import authentication.api.utils as utils


class UtilsTests(unittest.TestCase):
    def test_create_and_decode(self):
        credentials = {"identifier": "123", "username": "test@factioninc.com", "password": "password"}
        jwt_token = utils.create_jwt_token(credentials, os.getenv("AUTH_PRIV_KEY"), expire=None)
        s = jwt.decode(jwt_token, os.getenv('AUTH_PUB_KEY'), algorithms=["RS512", "RS256"])
        self.assertTrue(s['username'] == 'test@factioninc.com')

    def test_create_jwt_token(self):
        credentials = {"identifier": "123", "username": "test@factioninc.com", "password": "password"}
        jwt_token = utils.create_jwt_token(credentials, os.getenv("AUTH_PRIV_KEY"), expire=None)
        self.assertIsNotNone(jwt_token)

    def test_decode_jwt_token(self):
        s = jwt.decode(
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJ1c2VybmFtZSI6InRlc3RAZmFjdGlvbmluYy5jb20iLCJyb2xlcyI6WyJhZG1pbiJdfQ.Yt2SbD9uvj-mmwCqdJvQanqxUCeERrWPFFCGCNelsqZk8-rv91ZlgpOXGavRnpx0Et8iViXqLNXnEOQetIDJO8mivXtezP9Q1Hrr2xw3gqcni5bM7BeUx13TmSf9YHjYhnmqn1g9Qyy6HLVduFnhBLBUOCI8KEOeKDfAmsKNX9u7NQNe0QSwn0lDW9eT751GFb_9DRjK0-WusOQ5Co_zoezook9igeoa6PLUYXSpt_35ZfqhCjMidn5lMKWzec8MQUHVFjiYiwtxdx6uoMYqAlr1ofg6Okm6xzDQWh8BaC9jqpbEmooPE13WLdR9sFdWoTPmEKRvD73MC1iNQkLO5g",
            os.getenv('AUTH_PUB_KEY'), algorithms=["RS512", "RS256"])
        self.assertTrue(s['username'] == 'test@factioninc.com')
        print(s)

    def test_hash_pwd(self):
        result = utils.hash_pwd('password')
        self.assertIsNotNone(result)

    def test_compare_pwd_with_hash(self):
        hashed_password = utils.hash_pwd('password')
        self.assertTrue(
            utils.compare_pwd_with_hash("password", hashed_password.split('.')[0], hashed_password.split('.')[1]))


if __name__ == '__main__':
    unittest.main()
