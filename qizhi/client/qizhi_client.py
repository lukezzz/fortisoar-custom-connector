import json
import os.path
import re
from typing import Optional

import requests
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('qizhi')


class QizhiClient:
    def __init__(self, config):
        self.base_url = config.get('api_server_ip').strip()
        if not self.base_url.startswith(('https://', "http://")):
            self.base_url = 'https://' + self.base_url
        self._verify = config.get('verify_ssl', False)
        self.password = config['admin_pwd']
        self.username = config['admin_user']
        self._token = ''
        self._cookie = ''
        self.match = []

    def authenticate(self):
        if self._token == '':
            return False
        else:
            return True

    def login(self):
        # try:
        request_payload = {'username': self.username, 'password': self.password}
        resp = self.connect('POST', 'authenticate', request_payload)
        if resp["code"] != 0 and not resp["data"].get("ST_AUTH_TOKEN"):
            # raise ConnectorError('Authenticate Failed')
            return {"code": 1003, "msg": "Authenticate Failed", "data": ""}
        self._token = str(resp["data"]['ST_AUTH_TOKEN'])
        return {"code": 0, "msg": "ok", "data": "ok"}
        # except Exception as err:
        #     logger.error(err)
        #     raise ConnectorError(err)

    def connect(self, method, resource, data=None) -> dict:
        headers = {
            'Content-Type': 'application/json',
            "Accept": "application/json, text/javascript, */*; q=0.01"
        }
        if self._token != '':
            headers['st-auth-token'] = self._token
        # Only convert the data to JSON if there is data.
        if data is not None and method != 'GET':
            data = json.dumps(data)
        url = os.path.join(self.base_url, "shterm/api", resource)
        # url = "{0}//{1}".format(self.base_url, resource)
        try:
            session = requests.Session()
            if method == 'POST':
                response = session.post(url, data=data, headers=headers, verify=self._verify)
            elif method == 'PUT':
                response = session.put(url, data=data, headers=headers, verify=self._verify)
            elif method == 'DELETE':
                response = session.delete(url, data=data, headers=headers, verify=self._verify)
            else:
                response = session.get(url, params=data, headers=headers, verify=self._verify)
        # except requests.exceptions.SSLError as e:
        #     # logger.exception('{}'.format(e))
        #     # raise ConnectorError('SSL certificate validation failed')
        #     return {"code": 1001, "msg": "SSL certificate validation failed", "data": ""}
        except requests.ConnectionError as e:
            # logger.exception('{}'.format(e))
            # raise ConnectorError('{}'.format(e))
            return {"code": 1001, "msg": "connect error", "data": ""}

        # except Exception as e:
        #     logger.exception('{}'.format(e))
        #     raise ConnectorError('{}'.format(e))
        try:
            return {"code": 0, "msg": "ok", "data": response.json()}
        except ValueError:
            return {"code": 1000, "msg": response.text, "data": ""}
