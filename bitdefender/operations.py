from .constants import *
from connectors.core.connector import ConnectorError, get_logger
import requests
import json
import uuid
logger = get_logger("bitdefender")


def get_account_list(
    config, params
):
    url = config.get("url")
    token = "Basic " + config.get("token")
    url = url + "/accounts"
    payload = json.dumps({
        "id": str(uuid.uuid4()),
        "jsonrpc": "2.0",
        "method": "getAccountList",
        "params": {
            "page": 1,
            "perPage": 10
        }
    })
    headers = {
        'Authorization': 'Basic ' + token,
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    if response.status_code != 200:
        raise ("Health check failed")
    return True


def get_endpoint_id(config, params):
    url = config.get("url")
    token = "Basic " + config.get("token")
    parent_id = config.get("parent_id")
    ip_address = params.get("ip_address")
    url = url + "/network"
    payload = json.dumps({
        "params": {
            "parentId": parent_id,
            "page": 1,
            "perPage": 3,
            "filters": {
                "security": {
                    "management": {
                        "managedWithBest": True,
                        "managedRelays": True
                    }
                }
            },
            "options": {
                "returnProductOutdated": True,
                "includeScanLogs": True
            }
        },
        "jsonrpc": "2.0",
        "method": "getEndpointsList",
        "id": str(uuid.uuid4())
    })
    headers = {
        'Authorization': 'Basic ' + token,
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    if response.status_code != 200:
        raise ("Failed in get point")
    print(response.json())
    for i in response.json().get("result").get("items"):
        if i['ip'] == ip_address:
            return i["id"]
    return None


def incidents_endpoint(config, params):
    url = config.get("url")
    token = config.get("token")
    endpoint_id = params.get("endpoint_id")
    url = url + "/incidents"
    payload = json.dumps({
    "id": str(uuid.uuid4()),
    "jsonrpc": "2.0",
    "method": "createIsolateEndpointTask",
    "params": {
        "endpointId": endpoint_id
    }
    })
    headers = {
        'Authorization': 'Basic ' + token,
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    if response.status_code != 200:
        raise ("Failed in incidents_endpoint")
    return response.json()

operations = {
    "get_account_list": get_account_list,
    "get_endpoint_id": get_endpoint_id,
    "incidents_endpoint": incidents_endpoint
}
