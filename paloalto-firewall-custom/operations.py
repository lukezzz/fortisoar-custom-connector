""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from .connections import *
from .constants import ADDRESS_TYPE, ADDRESS_GROUP, POLICY_ACTION
from connectors.core.connector import ConnectorError, get_logger

logger = get_logger("paloalto-firewall")


def check_payload(payload):
    updated_payload = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            nested = check_payload(value)
            if len(nested.keys()) > 0:
                updated_payload[key] = nested
        elif value != "" and value is not None:
            updated_payload[key] = value
    return updated_payload


def prepare_response(res):
    try:
        final_res = {
            "response": {
                "@code": res.get("@code"),
                "@status": res.get("@status"),
                "result": {"msg": {"line": res.get("msg")}},
            }
        }
        return final_res
    except Exception as err:
        logger.error("Failed to prepare response, error {0}".format(err))
        return res


def create_address_object(obj, params):
    try:
        data = {
            "entry": [
                {
                    "@name": params.get("ip").replace("/", "-"),
                    "ip-netmask": params.get("ip"),
                }
            ]
        }
        return obj.make_rest_call(
            endpoint="/Objects/Addresses",
            method="POST",
            params={"name": params.get("ip").replace("/", "-")},
            data=json.dumps(data),
        )
    except Exception as err:
        if "Object already exists" in str(err):
            pass
        else:
            raise ConnectorError(str(err))


def edit_address_group_object(obj, ip_value, action):
    try:
        previous_data = obj.make_rest_call(
            endpoint="/Objects/AddressGroups", params={"name": obj._address_group}
        )
        entries_list = previous_data.get("result").get("entry")
        if len(entries_list) == 1:
            members_list = entries_list[0].get("static", {}).get("member")
            if type(members_list) is not list:
                members_list = []
        else:
            raise ConnectorError("Input address group not found")
        if action == "ADD":
            members_list.append(ip_value)
        else:
            members_list.remove(ip_value)
        members_list = list(set(members_list))
        data = {
            "entry": [{"@name": obj._address_group, "static": {"member": members_list}}]
        }
        if len(members_list) == 0:
            data["entry"][0].pop("static")
        res = obj.make_rest_call(
            endpoint="/Objects/AddressGroups",
            method="PUT",
            params={"name": obj._address_group},
            data=json.dumps(data),
        )
        return prepare_response(res)
    except Exception as err:
        raise ConnectorError(str(err))


def edit_custom_url_category(obj, url, action):
    try:
        if len(obj._url_group) == 0 or len(obj._url_policy_name) == 0:
            raise ConnectorError(
                "Configure URL group/URL policy name to execute this action at connector configuration page"
            )
        previous_data = obj.make_rest_call(
            endpoint="/Objects/CustomURLCategories", params={"name": obj._url_group}
        )
        entries_list = previous_data.get("result").get("entry")
        if len(entries_list) == 1:
            members_list = entries_list[0].get("list", {}).get("member")
            if type(members_list) is not list:
                members_list = []
        else:
            raise ConnectorError("Input custom URL category not found")
        if action == "ADD":
            members_list.append(url)
        else:
            members_list.remove(url)
        members_list = list(set(members_list))
        data = {
            "entry": [
                {
                    "@name": obj._url_group,
                    "type": "URL List",
                    "list": {"member": members_list},
                }
            ]
        }
        if len(members_list) == 0:
            data["entry"][0].pop("list")
        res = obj.make_rest_call(
            endpoint="/Objects/CustomURLCategories",
            method="PUT",
            params={"name": obj._url_group},
            data=json.dumps(data),
        )

        # commit the changes
        commit_resp = check_response(obj)
        logger.debug("commit resp = {0}".format(commit_resp))

        return prepare_response(res)
    except Exception as err:
        raise ConnectorError(str(err))


def edit_application_group(obj, app, action):
    try:
        if len(obj._app_group) == 0 or len(obj._app_policy_name) == 0:
            raise ConnectorError(
                "Configure Application group/Application policy name to execute this action at connector "
                "configuration page"
            )
        previous_data = obj.make_rest_call(
            endpoint="/Objects/ApplicationGroups", params={"name": obj._app_group}
        )
        prev_app_list = previous_data.get("result").get("entry")
        if len(prev_app_list) == 1:
            members_list = prev_app_list[0].get("members", {}).get("member")
            if type(members_list) is not list:
                members_list = []
        else:
            raise ConnectorError("Input application group object not found")
        if action == "ADD":
            members_list.append(app)
        else:
            members_list.remove(app)
        members_list = list(set(members_list))
        data = {
            "entry": [{"@name": obj._app_group, "members": {"member": members_list}}]
        }
        if len(members_list) == 0:
            data["entry"][0].pop("members")
        res = obj.make_rest_call(
            endpoint="/Objects/ApplicationGroups",
            method="PUT",
            params={"name": obj._app_group},
            data=json.dumps(data),
        )

        # commit the changes
        commit_resp = check_response(obj)
        logger.debug("commit resp = {0}".format(commit_resp))

        return prepare_response(res)
    except Exception as err:
        raise ConnectorError(str(err))


def block_ip(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        create_address_object(obj, params)
        resp = edit_address_group_object(
            obj, params.get("ip").replace("/", "-"), action="ADD"
        )

        # commit the changes
        commit_resp = check_response(obj)
        logger.debug("commit resp = {0}".format(commit_resp))
        return resp
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def unblock_ip(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        params["ip"] = params.get("ip").replace("/", "-")
        res = edit_address_group_object(obj, params.get("ip"), action="DELETE")
        resp = obj.make_rest_call(
            endpoint="/Objects/Addresses",
            method="DELETE",
            params={"name": params.get("ip")},
        )

        # commit the changes
        commit_resp = check_response(obj)
        logger.debug("commit resp = {0}".format(commit_resp))

        return resp
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def block_url(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        return edit_custom_url_category(obj, params.get("url"), action="ADD")
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def unblock_url(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        return edit_custom_url_category(obj, params.get("url"), action="DELETE")
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def block_application(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        return edit_application_group(obj, params.get("app"), action="ADD")
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def unblock_application(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        return edit_application_group(obj, params.get("app"), action="DELETE")
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def create_payload(params):
    payload = {
        "entry": {
            "@name": params.get("name"),
            "from": {
                "member": params.get("from").split(",") if params.get("from") else []
            },
            "to": {"member": params.get("to").split(",") if params.get("to") else []},
            "source": {
                "member": (
                    params.get("source").split(",") if params.get("source") else []
                )
            },
            "destination": {
                "member": (
                    params.get("destination").split(",")
                    if params.get("destination")
                    else []
                )
            },
            "service": {
                "member": (
                    params.get("service").split(",") if params.get("service") else []
                )
            },
            "application": {
                "member": (
                    params.get("application").split(",")
                    if params.get("application")
                    else []
                )
            },
            "action": (
                POLICY_ACTION.get(params.get("action")) if params.get("action") else ""
            ),
            "category": {
                "member": (
                    params.get("category").split(",") if params.get("category") else ""
                )
            },
            "source-user": {
                "member": (
                    params.get("source-user").split(",")
                    if params.get("source-user")
                    else ""
                )
            },
            "rule-type": (
                params.get("rule-type").lower() if params.get("rule-type") else ""
            ),
            "disabled": params.get("disable").lower() if params.get("disable") else "",
        }
    }
    if params.get("attributes"):
        payload["entry"].update(params.get("attributes"))
    payload = check_payload(payload)
    return payload


def create_security_rule(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        payload = create_payload(params)
        return obj.make_rest_call(
            endpoint="/Policies/SecurityRules",
            method="POST",
            data=json.dumps(payload),
            params={"name": params.get("name")},
        )
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def list_security_rule(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        query_params = check_payload(params)
        return obj.make_rest_call(
            endpoint="/Policies/SecurityRules", method="GET", params=query_params
        )
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def edit_security_rule(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        payload = create_payload(params)
        return obj.make_rest_call(
            endpoint="/Policies/SecurityRules",
            method="PUT",
            data=json.dumps(payload),
            params={"name": params.get("name")},
        )
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def rename_security_rule(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        return obj.make_rest_call(
            endpoint="/Policies/SecurityRules:rename", method="POST", params=params
        )
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def move_security_rule(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        query_params = {
            "name": params.get("name"),
            "where": params.get("where").lower(),
            "dst": params.get("dst"),
        }
        query_params = check_payload(query_params)
        return obj.make_rest_call(
            endpoint="/Policies/SecurityRules:move", method="POST", params=query_params
        )
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def delete_security_rule(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        return obj.make_rest_call(
            endpoint="/Policies/SecurityRules", method="DELETE", params=params
        )
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def create_address(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        payload = {
            "entry": {
                ADDRESS_TYPE.get(params.get("address_type")): params.get("value"),
                "@name": params.get("name"),
                "tag": (
                    {"member": params.get("tag").split(",")}
                    if params.get("tag")
                    else ""
                ),
                "description": params.get("description"),
            }
        }
        payload = check_payload(payload)
        return obj.make_rest_call(
            endpoint="/Objects/Addresses",
            method="POST",
            data=json.dumps(payload),
            params={"name": params.get("name")},
        )
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def get_address_list(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        return obj.make_rest_call(
            endpoint="/Objects/Addresses", method="GET", params={}
        )
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def get_address_details(config, params):
    obj = PaloAltoCustom(config)
    try:
        return obj.make_rest_call(
            endpoint="/Objects/Addresses", method="GET", params=params
        )
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def edit_address(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        tag = params.get("tag")
        description = params.get("description")
        if not tag:
            check_tag = (
                get_address_details(config, params).get("result")["entry"][0].get("tag")
            )
            if check_tag:
                tag = ",".join(check_tag["member"])
            else:
                tag = ""
        if not description:
            description = get_address_details(config, params).get("result")["entry"][0][
                "description"
            ]
        payload = {
            "entry": {
                ADDRESS_TYPE.get(params.get("address_type")): params.get("value"),
                "@name": params.get("name"),
                "tag": {"member": tag.split(",")} if tag else "",
                "description": description,
            }
        }
        payload = check_payload(payload)
        return obj.make_rest_call(
            endpoint="/Objects/Addresses",
            method="PUT",
            data=json.dumps(payload),
            params={"name": params.get("name")},
        )
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def rename_address(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        return obj.make_rest_call(
            endpoint="/Objects/Addresses:rename", method="POST", params=params
        )
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def delete_address(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        return obj.make_rest_call(
            endpoint="/Objects/Addresses", method="DELETE", params=params
        )
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def create_address_group(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        payload = {
            "entry": {
                params.get("address_group").lower(): {
                    ADDRESS_GROUP.get(params.get("address_group")): (
                        params.get("member").split(",")
                        if params.get("address_group") == "Static"
                        else params.get("filter")
                    )
                },
                "@name": params.get("name"),
                "tag": (
                    {"member": params.get("tag").split(",")}
                    if params.get("tag")
                    else ""
                ),
                "description": params.get("description"),
            }
        }
        payload = check_payload(payload)
        return obj.make_rest_call(
            endpoint="/Objects/AddressGroups",
            method="POST",
            data=json.dumps(payload),
            params={"name": params.get("name")},
        )
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def get_address_group_list(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        return obj.make_rest_call(
            endpoint="/Objects/AddressGroups", method="GET", params={}
        )
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def get_address_group(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        return obj.make_rest_call(
            endpoint="/Objects/AddressGroups", method="GET", params=params
        )
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def rename_address_group(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        return obj.make_rest_call(
            endpoint="/Objects/AddressGroups:rename", method="POST", params=params
        )
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def add_delete_to_specific_group(obj, ip_value, action, name):
    try:
        previous_data = obj.make_rest_call(
            endpoint="/Objects/AddressGroups", method="GET", params={"name": name}
        )
        entries_list = previous_data.get("result").get("entry")
        if len(entries_list) == 1:
            members_list = entries_list[0].get("static", {}).get("member")
            if type(members_list) is not list:
                members_list = []
        else:
            raise ConnectorError("Input address group not found")
        if action == "ADD":
            members_list.append(ip_value)
        else:
            members_list.remove(ip_value)
        members_list = list(set(members_list))
        data = {"entry": [{"@name": name, "static": {"member": members_list}}]}
        if len(members_list) == 0:
            data["entry"][0].pop("static")
        res = obj.make_rest_call(
            endpoint="/Objects/AddressGroups",
            method="PUT",
            params={"name": name},
            data=json.dumps(data),
        )
        return prepare_response(res)

    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def add_address_to_specific_group(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        return add_delete_to_specific_group(
            obj, params.get("ip"), "ADD", params.get("name")
        )
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def remove_address_from_specific_group(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        return add_delete_to_specific_group(
            obj, params.get("ip"), "DELETE", params.get("name")
        )
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def delete_address_group(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        return obj.make_rest_call(
            endpoint="/Objects/AddressGroups", method="DELETE", params=params
        )
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def rest_check_health(config):
    try:
        obj = PaloAltoCustom(config)
        res = obj.make_rest_call(endpoint="/Policies/SecurityRules", params={})
    except Exception as err:
        # err.args[0]["code"]  # request ok if type of err.args[0] is dict
        if "Not Authenticated" not in str(err):
            raise ConnectorError(str(err))


operations = {
    "block_ip": block_ip,
    "unblock_ip": unblock_ip,
    "block_url": block_url,
    "unblock_url": unblock_url,
    "block_app": block_application,
    "unblock_app": unblock_application,
    "create_security_rule": create_security_rule,
    "list_security_rule": list_security_rule,
    "edit_security_rule": edit_security_rule,
    "delete_security_rule": delete_security_rule,
    "rename_security_rule": rename_security_rule,
    "move_security_rule": move_security_rule,
    "create_address": create_address,
    "get_address_list": get_address_list,
    "get_address_details": get_address_details,
    "edit_address": edit_address,
    "rename_address": rename_address,
    "delete_address": delete_address,
    "create_address_group": create_address_group,
    "get_address_group_list": get_address_group_list,
    "get_address_group": get_address_group,
    "rename_address_group": rename_address_group,
    "add_address_to_specific_group": add_address_to_specific_group,
    "remove_address_from_specific_group": remove_address_from_specific_group,
    "delete_address_group": delete_address_group,
}
