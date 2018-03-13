import base64
import os
import uuid
import unittest
from unittest import mock
from unittest.mock import patch, Mock
from requests import Response
import json

import services.services

from authentication.api.auth_methods import FactionAuthAPI

MOCK_CMDB_HOST = 'http://cmdb/api'
MOCK_AUTH_PRIV_KEY = '1234'
MOCK_RABBIT_HOST = 'amqp://mock'


def mock_os_getenv(key, default=None):
    if key == 'CMDB_HOST':
        return MOCK_CMDB_HOST
    if key == 'RABBIT_HOST':
        return MOCK_RABBIT_HOST
    if key == 'AUTH_PRIV_KEY':
        return base64.b64decode(
            'LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBdDVFeVpxL2c3WEVLajlOZzRVVFVJbU9lb3R4NmNKOUFtWUpSa3VOQ3dLOE9uRjN1ClgzYVJ0UWZqeWlTaDJJSnhGdkVTRzAzNDZJL1FuaGVUUU8zVDF4S3RKZ2dCRGlmNldsYU5wTDFaM2lmbmRDcUgKTDVKQ0U0YmlhcUVCVTkzd2N3ZjVXNG9MS3pVV3JWM2hZdC83NHRGQXZUd1kzaVdyL3NVY0R3bk5IalF3SkZHaQptMU1MZ2c4RHNKNTBRcXFLVW5RU2kvVlBQRXJpNk9PWVpISE1HcFNEd0lWOUxxMkZ2ejBqQzZEOUxNaGlKYWVmClJPVjFyc1E4UjdpczM1eWZoTkxBQ3dRWk1pMDRmcU5PQmFBK3hhWkFWYnNOUWpSZDU1dUxyRkxsMnZrckZoMHkKS1NyWU9ub0E5dy9zdnlNNmZ4Ym0zK2gwNGd4SXFxM0d4MEt3Y3dJREFRQUJBb0lCQVFDemF6K1FEcWdTYkVLZQpnVVJYNmlaTjFvRGZQaENPczVrNGNaKzVxbGM4YmQ0aUI4MU5rVjZwU3FUaWx4dDV1MFU5M3pLTGJaS3ovSjB6CmFHZU5OdWV2ZDVtMWFtMWRvTVdhTnE4TExlZ0FzNUFPZ3VMUEpHMWhHSjJGQ3dsNUo1dzFVcjN2TXVYbnZXUUUKMzVYRVJwaTBBVUw5c3hlN1NhYnF4VTIvaFJ6dlB2czFKY01PRzRvdGxLWmhSMXFoNkltNFkzcmpmNEs1L09GMwp1NVFSbmdaWEpVTDh1WjVuLzIrektUTmwvajlIeWsycUtoMlRwdGljV3lUVFEzU0kvRlFYRWFOVEFtY3dKczBBClZ5M1REQW42R2FPSTBnYllxeFRhU2xvQzdTQW5Mb3NheXVSZ210L1JvSkY4cVF5U25mbEtWZlk3c1ZHRGtEOTkKa0dHWVRtZEJBb0dCQU4reE02UksxTnQ4RFpSempkdjFnV0JDWFVVMHp1UjBYN0xzYkp4ZjlrOGt0Wkp0a1FRRwpLRnIwN013QW8vKytNYms1SU9sc0RtUHZ0ekNsMU1ZVmdBcEtIdnRqSDRmQWVST2p0S3hDenRDY0t1Nmw3QklZClhhYm5qQWdXZ1ZrZmR4emdobzRRcTBSRmVRRmVldU9pUUVBRnJLanY1b2tLUTlCbVRhblZGOWZYQW9HQkFOSVUKYVlLeDh3TWhXS3VjS0o5TVdVeTNnWHJLOFhKU0FlZmU3emRPQ3FpMW4rclRabkRuTFpDa2pSL2s5NGlkTW9pZApSTGliQlVCNkFpTmsyc0lodmxkUllTU1Yxbld1cG9EWGx5RzhjcjIzUTJDankvb2hLcWE4cXJCamo5M3NseDJ0CnJ2RnNDMU56bEdDRHFZNkVkei9CcEk2QUczSXpxZVJ2Ni81NVVDakZBb0dBRlZZR2tmWWRSVzRZc1g4d0dibmEKQkQ5d1BBaWtiei8yWE0rV01IZ3F1elBLS2RSUGo2MnlyYkpNMzh4ejJCSGhGa1N2c2ZQL2oyS3UrM0hsMEpyKwpZbnpkWmFiM3UvQU0zR1d4OXZoTVY3TjltTk8wcDZreFRaa3FUeDh1YVR6S0ZMUUp3WVV2Z015TGxTalkyZHVBCisxcFBOTEhsTUU4TlZ0UmJOZ2JBUm5NQ2dZQVFnSUg1UGprMG1iMzVYUDdqNUg5dlEwcnNkbHlZK2xBa0FxTVAKMlJXRlF4OFl0eHBvNi8vc1NNQzlMS00xSEFRSUx6Sml2ZXFmc2ZYUkNlOFZLTWxtMm9HaStoSXFsRm1IN1dkMQp3dlBRYTBEanFub3ZYOE9WN1dRTER3Y1NDNitqS1MyQTBWZmlha1hSZndZbXA4a21QUFBNTGN2NklJekw0TzdNCndvTEZjUUtCZ0FmZnJVOGNOS05WL1NKK1FmUVowKzNtZEwyT2ZNUEs3VUFKN2FYWmUzUnpLaTFrdDhtNlQvUEkKSldUTWM2a1BkOHdXSXNRaHB2R2R2T0ErdnlTNUpwZG4rYzdSOWRZWGxFK1RlZGMwZ3ZXS3RvcmtnSzdGR0owRQowcXpDUnZqcWtzWk5pUElyRDJVU2dJSUx5WHBSYWh4QXFtVWlHVk4rZVJ2cHFOblZQUWZsCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg==')
    if key == 'AUTH_PUB_KEY':
        return base64.b64decode(
            'c3NoLXJzYSBBQUFBQjNOemFDMXljMkVBQUFBREFRQUJBQUFCQVFDM2tUSm1yK0R0Y1FxUDAyRGhSTlFpWTU2aTNIcHduMENaZ2xHUzQwTEFydzZjWGU1ZmRwRzFCK1BLSktIWWduRVc4UkliVGZqb2o5Q2VGNU5BN2RQWEVxMG1DQUVPSi9wYVZvMmt2Vm5lSitkMEtvY3Zra0lUaHVKcW9RRlQzZkJ6Qi9sYmlnc3JOUmF0WGVGaTMvdmkwVUM5UEJqZUphdit4UndQQ2MwZU5EQWtVYUtiVXd1Q0R3T3dublJDcW9wU2RCS0w5VTg4U3VMbzQ1aGtjY3dhbElQQWhYMHVyWVcvUFNNTG9QMHN5R0lscDU5RTVYV3V4RHhIdUt6Zm5KK0Uwc0FMQkJreUxUaCtvMDRGb0Q3RnBrQlZ1dzFDTkYzbm00dXNVdVhhK1NzV0hUSXBLdGc2ZWdEM0QreS9JenAvRnViZjZIVGlERWlxcmNiSFFyQnogdGNhcnJAVGltb3RoeXMtTWFjQm9vay1Qcm8ubG9jYWwK')


def mock_settings():
    pass


@patch('authentication.api.auth_methods.os.getenv', mock_os_getenv)
class TestFactionAuthAPI(unittest.TestCase):
    get_user_resp = [{'authmethod': 'faction',
                      'contactmethods': [{
                          'identifier': '00f2efbe-b8ac-42e3-b939-0bba2d34a070',
                          'name': 'Admin Email',
                          'uri': '/cmdb/general/contacts/00f2efbe-b8ac-42e3-b939-0bba2d34a070'}],
                      'defaultorg': {
                          'identifier': 'aabb63e1-6a77-4f44-8445-1310148071ec',
                          'name': 'Faction HQ',
                          'uri': '/cmdb/general/organizations/aabb63e1-6a77-4f44-8445-1310148071ec'},
                      'email': 'admin@factioninc.com',
                      'firstname': 'Faction',
                      'identifier': '55360491-e78a-47bd-95c1-cded9607c4e3',
                      'lastname': 'Admin',
                      'password': 'db227b3dca13855952dbca37fc8714d9a4a6412c61035ecf79ed0842e4270381.47a6282ea1e3f11d928a7cd1cc7da93dcdb5b2363bbcab43810d983777d31e78',
                      'state': 'registered',
                      'tags': None,
                      'uri': '/cmdb/general/users/55360491-e78a-47bd-95c1-cded9607c4e3',
                      'username': 'admin@factioninc.com'}]

    put_user_resp = {'authmethod': 'faction',
                     'contactmethods': [{
                         'identifier': 'a1bf67ee-91bf-4758-a911-d4f3303f37e8',
                         'name': 'Test sms 0',
                         'uri': '/cmdb/general/contacts/a1bf67ee-91bf-4758-a911-d4f3303f37e8'}],
                     'defaultorg': {
                         'identifier': '64bc8035-f4cf-48c3-bbe2-51bb5862d74f',
                         'name': 'Faction HQ',
                         'uri': '/cmdb/general/organizations/64bc8035-f4cf-48c3-bbe2-51bb5862d74f'},
                     'email': 'test0@none.none',
                     'firstname': 'test',
                     'identifier': '1443dd3d-815b-4880-b9dd-9ade9a686787',
                     'lastname': 'zero',
                     'password': '520f2cce563cd429d61be1131869e7b25d652f8b451e514cd5e5c3bdb15b304a.7092b55946f480c1a955c10855b086ca03c0beee33adfee5251c48f501635776',
                     'registrationstate': 'registered',
                     'tags': None,
                     'uri': '/cmdb/general/users/1443dd3d-815b-4880-b9dd-9ade9a686787',
                     'username': 'test0'}

    orguserroles_resp = [
        {
            "identifier": "eac2821c-7b0e-4f31-8444-23f8e1e76fe2",
            "organization": {
                "identifier": "d10dcc6f-ac59-48cd-9c98-11612d3113b2",
                "name": "Faction HQ",
                "uri": "/cmdb/general/organizations/d10dcc6f-ac59-48cd-9c98-11612d3113b2"
            },
            "role": {
                "identifier": "e87b9f4e-9104-4b01-b869-b56e8bf14f1c",
                "name": "Faction Admin",
                "organization": None,
                "rights": [
                    {
                        "identifier": "068efd6f-649b-4ac2-9d95-7188eba9e366",
                        "permission": "GET",
                        "resource": "organizations",
                        "uri": "/cmdb/general/rights/068efd6f-649b-4ac2-9d95-7188eba9e366"
                    },
                    {
                        "identifier": "71257d66-cd9f-4cbb-98d0-59228942e59f",
                        "permission": "POST",
                        "resource": "organizations",
                        "uri": "/cmdb/general/rights/71257d66-cd9f-4cbb-98d0-59228942e59f"
                    },
                    {
                        "identifier": "91d7bf6c-5e77-4538-b66d-4d7ea5a3fb98",
                        "permission": "PUT",
                        "resource": "organizations",
                        "uri": "/cmdb/general/rights/91d7bf6c-5e77-4538-b66d-4d7ea5a3fb98"
                    },
                    {
                        "identifier": "421ca8b1-cbe8-4135-95ea-ed21790070f1",
                        "permission": "DELETE",
                        "resource": "organizations",
                        "uri": "/cmdb/general/rights/421ca8b1-cbe8-4135-95ea-ed21790070f1"
                    },
                    {
                        "identifier": "13fc2a6a-a8c7-425f-86c6-884cf4a19991",
                        "permission": "GET",
                        "resource": "users",
                        "uri": "/cmdb/general/rights/13fc2a6a-a8c7-425f-86c6-884cf4a19991"
                    },
                    {
                        "identifier": "7c53cf57-9c09-4ffc-b076-9c598eda1a34",
                        "permission": "POST",
                        "resource": "users",
                        "uri": "/cmdb/general/rights/7c53cf57-9c09-4ffc-b076-9c598eda1a34"
                    },
                    {
                        "identifier": "ade354d4-c7e0-4c67-b61c-9a5f9bd97c63",
                        "permission": "PUT",
                        "resource": "users",
                        "uri": "/cmdb/general/rights/ade354d4-c7e0-4c67-b61c-9a5f9bd97c63"
                    },
                    {
                        "identifier": "fe5da705-b351-458a-b688-8a8091f26e7a",
                        "permission": "DELETE",
                        "resource": "users",
                        "uri": "/cmdb/general/rights/fe5da705-b351-458a-b688-8a8091f26e7a"
                    },
                    {
                        "identifier": "e6fbb513-0f47-420b-a7da-e16049bd40f2",
                        "permission": "GET",
                        "resource": "roles",
                        "uri": "/cmdb/general/rights/e6fbb513-0f47-420b-a7da-e16049bd40f2"
                    },
                    {
                        "identifier": "42b91133-81cb-4221-9991-58b535c9db7d",
                        "permission": "POST",
                        "resource": "roles",
                        "uri": "/cmdb/general/rights/42b91133-81cb-4221-9991-58b535c9db7d"
                    },
                    {
                        "identifier": "57b4e46b-d2ab-45ff-a139-5e6116a0acbd",
                        "permission": "PUT",
                        "resource": "roles",
                        "uri": "/cmdb/general/rights/57b4e46b-d2ab-45ff-a139-5e6116a0acbd"
                    },
                    {
                        "identifier": "aec72bdd-89de-4aa2-a6bc-cdd0ce9351fc",
                        "permission": "DELETE",
                        "resource": "roles",
                        "uri": "/cmdb/general/rights/aec72bdd-89de-4aa2-a6bc-cdd0ce9351fc"
                    }
                ],
                "uri": "/cmdb/general/roles/e87b9f4e-9104-4b01-b869-b56e8bf14f1c"
            },
            "uri": "/cmdb/general/orguserroles/eac2821c-7b0e-4f31-8444-23f8e1e76fe2",
            "user": {
                "authmethod": "faction",
                "contactMethods": [
                    {
                        "identifier": "b58158b1-a052-4786-8b8a-9a2b3a2e98e0",
                        "name": "Admin Email",
                        "uri": "/cmdb/general/contacts/b58158b1-a052-4786-8b8a-9a2b3a2e98e0"
                    }
                ],
                "defaultorg": {
                    "identifier": "d10dcc6f-ac59-48cd-9c98-11612d3113b2",
                    "name": "Faction HQ",
                    "uri": "/cmdb/general/organizations/d10dcc6f-ac59-48cd-9c98-11612d3113b2"
                },
                "email": "admin@factioninc.com",
                "identifier": "2051bf8e-5d47-4b97-8cf8-8d5bfbf76b18",
                "password": "f661aad0786a7ea225994fb65768c7a419506a31c6329e7926a02a885367ba03.dadb3ca81d35c7495699dff8b8e688644baf9d8d82f1966639dffac8d594f6ee",
                "registrationState": "registered",
                "uri": "/cmdb/general/users/2051bf8e-5d47-4b97-8cf8-8d5bfbf76b18",
                "username": "admin@factioninc.com"
            }
        },
        {
            "identifier": "50bf5672-57dc-415d-974c-983cb6bb6f65",
            "organization": {
                "identifier": "0c45552e-ac9a-4dc8-8e02-fcb35f6a4b0f",
                "name": "Savage Tech",
                "uri": "/cmdb/general/organizations/0c45552e-ac9a-4dc8-8e02-fcb35f6a4b0f"
            },
            "role": {
                "identifier": "e87b9f4e-9104-4b01-b869-b56e8bf14f1c",
                "name": "Faction Admin",
                "organization": None,
                "rights": [
                    {
                        "identifier": "068efd6f-649b-4ac2-9d95-7188eba9e366",
                        "permission": "GET",
                        "resource": "organizations",
                        "uri": "/cmdb/general/rights/068efd6f-649b-4ac2-9d95-7188eba9e366"
                    },
                    {
                        "identifier": "71257d66-cd9f-4cbb-98d0-59228942e59f",
                        "permission": "POST",
                        "resource": "organizations",
                        "uri": "/cmdb/general/rights/71257d66-cd9f-4cbb-98d0-59228942e59f"
                    },
                    {
                        "identifier": "91d7bf6c-5e77-4538-b66d-4d7ea5a3fb98",
                        "permission": "PUT",
                        "resource": "organizations",
                        "uri": "/cmdb/general/rights/91d7bf6c-5e77-4538-b66d-4d7ea5a3fb98"
                    },
                    {
                        "identifier": "421ca8b1-cbe8-4135-95ea-ed21790070f1",
                        "permission": "DELETE",
                        "resource": "organizations",
                        "uri": "/cmdb/general/rights/421ca8b1-cbe8-4135-95ea-ed21790070f1"
                    },
                    {
                        "identifier": "13fc2a6a-a8c7-425f-86c6-884cf4a19991",
                        "permission": "GET",
                        "resource": "users",
                        "uri": "/cmdb/general/rights/13fc2a6a-a8c7-425f-86c6-884cf4a19991"
                    },
                    {
                        "identifier": "7c53cf57-9c09-4ffc-b076-9c598eda1a34",
                        "permission": "POST",
                        "resource": "users",
                        "uri": "/cmdb/general/rights/7c53cf57-9c09-4ffc-b076-9c598eda1a34"
                    },
                    {
                        "identifier": "ade354d4-c7e0-4c67-b61c-9a5f9bd97c63",
                        "permission": "PUT",
                        "resource": "users",
                        "uri": "/cmdb/general/rights/ade354d4-c7e0-4c67-b61c-9a5f9bd97c63"
                    },
                    {
                        "identifier": "fe5da705-b351-458a-b688-8a8091f26e7a",
                        "permission": "DELETE",
                        "resource": "users",
                        "uri": "/cmdb/general/rights/fe5da705-b351-458a-b688-8a8091f26e7a"
                    },
                    {
                        "identifier": "e6fbb513-0f47-420b-a7da-e16049bd40f2",
                        "permission": "GET",
                        "resource": "roles",
                        "uri": "/cmdb/general/rights/e6fbb513-0f47-420b-a7da-e16049bd40f2"
                    },
                    {
                        "identifier": "42b91133-81cb-4221-9991-58b535c9db7d",
                        "permission": "POST",
                        "resource": "roles",
                        "uri": "/cmdb/general/rights/42b91133-81cb-4221-9991-58b535c9db7d"
                    },
                    {
                        "identifier": "57b4e46b-d2ab-45ff-a139-5e6116a0acbd",
                        "permission": "PUT",
                        "resource": "roles",
                        "uri": "/cmdb/general/rights/57b4e46b-d2ab-45ff-a139-5e6116a0acbd"
                    },
                    {
                        "identifier": "aec72bdd-89de-4aa2-a6bc-cdd0ce9351fc",
                        "permission": "DELETE",
                        "resource": "roles",
                        "uri": "/cmdb/general/rights/aec72bdd-89de-4aa2-a6bc-cdd0ce9351fc"
                    }
                ],
                "uri": "/cmdb/general/roles/e87b9f4e-9104-4b01-b869-b56e8bf14f1c"
            },
            "uri": "/cmdb/general/orguserroles/50bf5672-57dc-415d-974c-983cb6bb6f65",
            "user": {
                "authmethod": "faction",
                "contactMethods": [
                    {
                        "identifier": "b58158b1-a052-4786-8b8a-9a2b3a2e98e0",
                        "name": "Admin Email",
                        "uri": "/cmdb/general/contacts/b58158b1-a052-4786-8b8a-9a2b3a2e98e0"
                    }
                ],
                "defaultorg": {
                    "identifier": "d10dcc6f-ac59-48cd-9c98-11612d3113b2",
                    "name": "Faction HQ",
                    "uri": "/cmdb/general/organizations/d10dcc6f-ac59-48cd-9c98-11612d3113b2"
                },
                "email": "admin@factioninc.com",
                "identifier": "2051bf8e-5d47-4b97-8cf8-8d5bfbf76b18",
                "password": "f661aad0786a7ea225994fb65768c7a419506a31c6329e7926a02a885367ba03.dadb3ca81d35c7495699dff8b8e688644baf9d8d82f1966639dffac8d594f6ee",
                "registrationState": "registered",
                "uri": "/cmdb/general/users/2051bf8e-5d47-4b97-8cf8-8d5bfbf76b18",
                "username": "admin@factioninc.com"
            }
        }
    ]

    def _mock_response(self, status=200, content="CONTENT", json_data=None, raise_for_status=None):
        """Helper function for creating responses

        We are likely to be mocking many requests. This helps building responses.
        """
        mock_resp = mock.Mock()
        # mock raise_for_status call w/optional error
        mock_resp.raise_for_status = mock.Mock()
        if raise_for_status:
            mock_resp.raise_for_status.side_effect = raise_for_status
        # set status code and content
        mock_resp.status_code = status
        mock_resp.content = content
        # add json data if provided
        if json_data:
            mock_resp.json = mock.Mock(
                return_value=json_data
            )
        return mock_resp

    def setUp(self):
        self.api = FactionAuthAPI()

    @patch('authentication.api.auth_methods.requests.get')
    def test_get_user_by_id(self, mock_get):
        mock_resp = self._mock_response(json_data=json.dumps(self.get_user_resp))
        mock_get.return_value = mock_resp
        user = FactionAuthAPI.get_user_by_id(1)
        self.assertIsNotNone(user)

    @patch('authentication.api.auth_methods.requests.get')
    def test_get_user_by_name(self, mock_get):
        mock_resp = self._mock_response(json_data=json.dumps(self.get_user_resp))
        mock_get.return_value = mock_resp
        user = FactionAuthAPI.get_user_by_name("some name")
        self.assertIsNotNone(user)

    @patch('authentication.api.auth_methods.requests.get')
    def test_get_user_by_email(self, mock_get):
        mock_resp = self._mock_response(json_data=json.dumps(self.get_user_resp))
        mock_get.return_value = mock_resp
        user = FactionAuthAPI.get_user_by_name("email")
        self.assertIsNotNone(user)

    @patch('authentication.api.auth_methods.compare_pwd_with_hash')
    @patch('authentication.api.auth_methods.requests.get')
    @patch('authentication.api.auth_methods.requests.put')
    @patch('authentication.api.auth_methods.requests.post')
    def test_set_user_password_by_id(self, mock_post, mock_put, mock_get, mock_compare):
        mock_resp_get = self._mock_response(json_data=self.get_user_resp)

        mock_resp_put = self._mock_response(json_data=self.put_user_resp)
        mock_put.return_value = mock_resp_put

        mock_get_password_history_resp = Response()
        mock_get_password_history_resp.status_code = 200
        mock_get_password_history_resp.json = Mock(return_value=[{
            'identifier': str(uuid.uuid4()),
            'user': str(uuid.uuid4()),
            'password': '!!!password!!!ABC'
        }])
        mock_get.side_effect = [mock_resp_get, mock_get_password_history_resp]

        mock_post_pwd_history_response = Response()
        mock_post_pwd_history_response.status_code = 201
        mock_post_pwd_history_response.json = Mock(return_value={
            'identifier': str(uuid.uuid4()),
            'user': str(uuid.uuid4()),
            'password': 'somepassword'
        })
        mock_post.return_value = mock_post_pwd_history_response

        # When comparing passwords, return false so doesn't fail password history check
        mock_compare.return_value = False

        user = FactionAuthAPI.set_user_password_by_id('user_id', 'new_pass', 'registered')
        self.assertIsNotNone(user)

    @patch('authentication.api.auth_methods.requests.get')
    @patch('authentication.api.auth_methods.requests.put')
    def set_user_password_by_name(self, mock_get, mock_put):
        mock_resp_get = self._mock_response(json_data=self.get_user_resp)
        mock_get.return_value = mock_resp_get

        mock_resp_put = self._mock_response(json_data=self.put_user_resp)
        mock_put.return_value = mock_resp_put

        user = FactionAuthAPI.set_user_password_by_name('user_name', 'new_pass', 'registered')
        self.assertIsNotNone(user)

    @patch('authentication.api.auth_methods.requests.get')
    def test_login(self, mock_get):
        mock_resp_get = self._mock_response(json_data=self.get_user_resp)
        mock_get.return_value = mock_resp_get
        credentials = {'username': 'admin@factioninc.com', 'password': 'password'}
        result = FactionAuthAPI.login(credentials)
        self.assertIsNotNone(result)

    @patch('authentication.api.auth_methods.kv.get')
    @patch('authentication.api.auth_methods.kv.delete')
    def test_logout(self, mock_kv_delete, mock_kv_get):
        token = 'some_token'
        mock_kv_delete.return_value = None
        mock_kv_get.return_value = token
        FactionAuthAPI.logout(token)

    @patch('authentication.api.auth_methods.requests.get')
    def test_create_session_details_for_user_id(self, mock_get):
        mock_resp_get = self._mock_response(json_data=self.get_user_resp)
        mock_get.return_value = mock_resp_get
        result = FactionAuthAPI.create_session_details_for_user_id('id')
        self.assertIsNotNone(result)

    @patch('authentication.api.auth_methods.requests.get')
    def test_create_session_details_for_user_name(self, mock_get):
        mock_resp_get = self._mock_response(json_data=self.get_user_resp)
        mock_get.return_value = mock_resp_get
        result = FactionAuthAPI.create_session_details_for_user_name('name')
        self.assertIsNotNone(result)

    def test_decode_jwt_token(self):
        session_details = {'identifier': 'my_id', 'username': 'my_username', 'roles': []}
        token = services.services.create_jwt_token(session_details, os.getenv('AUTH_PRIV_KEY'))
        result = services.services.decode_jwt_token(token, os.getenv('AUTH_PUB_KEY'))
        self.assertIsNotNone(result)
