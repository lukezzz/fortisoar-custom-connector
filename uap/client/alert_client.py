import json
import os.path
import re
from datetime import datetime
from typing import Optional

import requests
from connectors.core.connector import get_logger, ConnectorError

# from client.request_body import ALERT_SEND_DATA

logger = get_logger("uap")

priority_map = {
    "未知": "0",
    "信息": "1",
    "警告": "2",
    "异常": "3",
    "严重": "4",
    "灾难": "5",
    "恢复": "-1",
}


class AlertClient:
    def __init__(self, config):
        self.base_url = config["base_url"]
        logger.debug("base_url: {}".format(self.base_url))
        logger.debug("config: {}".format(config))
        if not self.base_url.startswith(("https://", "http://")):
            self.base_url = "https://" + self.base_url
        self._verify = config.get("verify_ssl", False)
        self.username = config.get("username", "")
        self.password = config.get("password", "")
        self.alert_id = config["alert_id"]
        self.host_name = config.get("host_name", "")
        self.host_ip = config.get("host_ip", "")
        self.host_id = config.get("host_id", "")
        self.contact = config.get("contact", "")
        self.app_contact = config.get("app_contact", "")
        self.device_contact = config.get("device_contact", "")
        self.send_to = config.get("send_to", "")
        self.alert_type = config.get("alert_type", "")
        self.alert_url = config.get("alert_url", "")
        self._token = ""
        self._cookie = ""

    def authenticate(self):
        if self._token == "":
            return False
        else:
            return True

    def login(self):
        pass
        # try:
        #     request_payload = {'username': self.username, 'password': self.password}
        #     resp = self.connect('POST', 'authenticate', request_payload)
        #     if not resp.get("ST_AUTH_TOKEN"):
        #         raise ConnectorError('Authenticate Failed')
        #     if resp is not None:
        #         self._token = str(resp['ST_AUTH_TOKEN'])
        # except Exception as err:
        #     logger.error(err)
        #     raise ConnectorError(err)

    # def logout(self):
    #     self.connect('DELETE', 'token')
    #     self._token = ''
    #     self._cookie = ''
    def alert_data(self, issue: str, priority: str):
        if self._token != "" and self.username and self.password:
            self.login()
        now = datetime.now()
        data = {
            "host_name": self.host_name,  # 字符串，告警主机名称
            "host_ip": self.host_ip,  # 字符串，告警主机IP
            "issue": issue,  # 必填，字符串，告警信息
            "groups": {  # 对象，告警分组信息
                "dt_groups": [],  # 对象，group_name 告警设备硬件分组 group_id 告警设备分组id
                "bs_groups": [],  # 对象，group_name 告警设备业务分组 group_id 告警业务分组id
            },
            "host_id": self.host_id,  # 字符，告警主机id
            "id": self.alert_id,  # 必填，字符，第三方告警id
            "last_change": now.strftime(
                "%m-%d %H:%M"
            ),  # 必填，字符，告警发生时间： mm-dd HH:MM
            "last_change_year": now.strftime(
                "%Y-%m-%d %H:%M"
            ),  # 必填，字符，告警发生时间： yyyy-mm-dd HH:MM
            "send_to": self.send_to,  # 数组，直接发送的告警联系人数组，与监控系统保持一致。
            "priority": priority_map[priority],  # 必填，字符，告警级别
            "actions": {},  # 告警发送信息
            "acknowledged": "0",  # 告警确认信息
            "tags": [],  # 告警标签
            "contact": self.contact,  # 告警联系人
            "app_contact": self.app_contact,  # 应用负责人
            "device_contact": self.device_contact,  # 设备负责人
            "alert_type": self.alert_type,  # 第三方告警平台名称
            "url": self.alert_url,  # 第三方告警平台地址，跳转url
            "applications": [],  # 数组，应用集名称
        }
        try:
            res = self.connect("POST", "/api/alert/exalert/sdata/", data=data)
            return res
        except Exception as e:
            raise ConnectorError("{}".format(e))

    def connect(self, method, resource, data=None) -> Optional[dict]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/javascript, */*; q=0.01",
        }
        if self._token != "":
            headers["token"] = self._token
        # Only convert the data to JSON if there is data.
        if data is not None and method != "GET":
            data = json.dumps(data)
        url = os.path.join(self.base_url, resource)
        # logger.debug("url: {}".format(url))
        url = "{0}{1}".format(self.base_url, resource)
        try:
            session = requests.Session()
            if method == "POST":
                response = session.post(
                    url, data=data, headers=headers, verify=self._verify
                )
            elif method == "PUT":
                response = session.put(
                    url, data=data, headers=headers, verify=self._verify
                )
            elif method == "DELETE":
                response = session.delete(
                    url, data=data, headers=headers, verify=self._verify
                )
            else:
                response = session.get(
                    url, params=data, headers=headers, verify=self._verify
                )
        except requests.exceptions.SSLError as e:
            logger.exception("{}".format(e))
            raise ConnectorError("SSL certificate validation failed")
        except Exception as e:
            logger.exception("{}".format(e))
            raise ConnectorError(e)
        except requests.ConnectionError as e:
            logger.exception("{}".format(e))
            raise ConnectorError("{}".format(e))
        try:
            return response.json()
        except ValueError:
            return None
