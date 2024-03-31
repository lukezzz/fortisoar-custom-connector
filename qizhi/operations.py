"""
This file will be auto-generated on each "new operation action", so avoid editing in this file.
"""

import re
import base64

import requests
from connectors.core.connector import get_logger, ConnectorError

from .client.qizhi_client import QizhiClient

logger = get_logger("qizhi")


def get_credential(config, params):
    c = QizhiClient(config)
    resp = c.login()
    if resp["code"] != 0:
        return resp
    account = params["account"]
    address = params["address"]
    data = {"userName": config["admin_user"], "account": account, "address": address}
    return c.connect("GET", "account/queryWorksheetPassword", data=data)
    # # if re.search("无法获取|不具备查看", str(resp)):
    # #     result["msg"] = resp
    # #     result["status"] = "invalid"
    # # else:
    # #     result["status"] = "valid"
    # #     result["pwd"] = base64.b64encode(str(resp["password"]).encode("U8")).decode("U8")
    # return {"code": 1000, "msg":}


def _check_health(config):
    c = QizhiClient(config)
    resp = c.login()
    if resp["code"] != 0:
        logger.exception("{}".format(resp["msg"]))
        raise ConnectorError("{}".format(resp["msg"]))


operations = {
    "get_credential": get_credential,
}
