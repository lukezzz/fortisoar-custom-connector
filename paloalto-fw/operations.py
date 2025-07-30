from .connections import *
from .constants import ADDRESS_TYPE, ADDRESS_GROUP, POLICY_ACTION
from connectors.core.connector import ConnectorError, get_logger
from ipaddress import ip_address, ip_network
from xml.etree import ElementTree
from datetime import datetime, timedelta, timezone
import json
import requests


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


def get_zone(config, params):
    """
    Perform a FIB Lookup for a given IP in a given Virtual Router and find
    the outgoing interface, then find the zone of the outgoing interface.
    """

    virtualrouter = (
        params.get("virtualrouter") if params.get("virtualrouter") else "default"
    )
    try:
        ip = ip_network(params.get("test_ip"), strict=False)
        test_ip = str(ip.network_address)
    except ValueError:
        raise ConnectorError("Invalid IP address")

    try:
        pa = PaloAltoCustom(config, params)
        pa.setupApiKey(params["username"], params["password"])
        # test ip and find the outgoing interface
        payload = {
            "type": "op",
            "cmd": "<test><routing><fib-lookup>"
            "<virtual-router>{}</virtual-router>"
            "<ip>{}</ip>"
            "</fib-lookup></routing></test>".format(virtualrouter, test_ip),
            "key": pa._key,
        }
        res_text = pa.make_xml_call(data=payload)
        tree = ElementTree.fromstring(res_text)
        if tree.find("result/interface") is None:
            raise ConnectorError("No outgoing interface found")
        outgoing_interface = tree.find("result/interface").text

        # get zone of the outgoing interface
        payload = {
            "type": "op",
            "cmd": "<show><interface>{}</interface></show>".format(
                outgoing_interface,
            ),
            "key": pa._key,
        }
        res_text = pa.make_xml_call(data=payload)
        tree = ElementTree.fromstring(res_text)
        zone = tree.find("result/ifnet/zone").text
        if not zone:
            raise ConnectorError("No zone found")

        # find the target zone
        return zone

    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def get_ha_status(config, params):
    try:
        pa = PaloAltoCustom(config, params)
        pa.setupApiKey(params["username"], params["password"])
        payload = {
            "type": "op",
            "cmd": "<show><high-availability><state></state></high-availability></show>",
            "key": pa._key,
        }
        res_text = pa.make_xml_call(data=payload)
        tree = ElementTree.fromstring(res_text)
        check_ha_enable = tree.find("result/enabled").text
        if check_ha_enable == "no":
            # HA is not enabled, and use current ip
            return True

        # check if current device is active or passive
        check_ha_state = tree.find("result/group/local-info/state").text
        if check_ha_state == "active":
            return True
        return False

    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def create_address(config, params):
    try:
        pa = PaloAltoCustom(config, params)
        pa.setupApiKey(params["username"], params["password"])

        post_addresses = params.get("addresses")
        addr_name_list = []
        for addr in post_addresses:

            try:
                obj = ip_network(addr, False)
                net = obj.network_address
                if str(net) == "0.0.0.0":
                    addr_name_list.append("any")
                    continue
                mask = int(obj.prefixlen)
                if mask == 32:
                    name = f"Host_{str(net)}"
                    ip = f"{net}/{mask}"
                else:
                    name = f"Network_{str(net)}_{mask}"
                    ip = f"{str(net)}/{mask}"

            except ValueError:
                logger.error("Invalid IP network", addr)
                continue

            payload = {
                "entry": {
                    "@name": name,
                    "description": "fortisoar",
                    "ip-netmask": ip,
                }
            }
            payload = check_payload(payload)
            try:
                res = pa.make_rest_call(
                    endpoint="/Objects/Addresses",
                    method="POST",
                    data=json.dumps(payload),
                    params={"name": name},
                )
            except Exception as err:
                logger.error("Failed to create address, error {0}".format(err))
                if "Object Not Unique" in str(err):
                    addr_name_list.append(name)
                continue

            # create successfully
            if res:
                addr_name_list.append(name)

        return addr_name_list
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def create_service(config, params):
    try:
        pa = PaloAltoCustom(config, params)
        pa.setupApiKey(params["username"], params["password"])

        port_list = params.get("port_list")
        protocol_list = params.get("protocol_list")

        service_name_list = []
        # for port, protocol in zip(port_list, protocol_list):
        #     service_list.append(
        #         {
        #             "port": port,
        #             "protocol": protocol,
        #             "name": f"{protocol.upper()}_{port}",
        #         }
        #     )
        service_list = [
            {"port": port, "protocol": protocol, "name": f"{protocol.upper()}_{port}"}
            for port in port_list
            for protocol in protocol_list
        ]
        for srv in service_list:
            # protocol only support tcp, udp
            protocol_type = (
                srv["protocol"].lower()
                if srv["protocol"].lower() in ["tcp", "udp"]
                else "tcp"
            )

            payload = {
                "entry": {
                    "@name": srv["name"],
                    "description": "fortisoar",
                    "protocol": {
                        protocol_type: {
                            "port": srv["port"],
                        }
                    },
                }
            }
            payload = check_payload(payload)
            try:
                res = pa.make_rest_call(
                    endpoint="/Objects/Services",
                    method="POST",
                    data=json.dumps(payload),
                    params={"name": srv["name"]},
                )
            except Exception as err:
                logger.error("Failed to create service, error {0}".format(err))
                if "Object Not Unique" in str(err):
                    service_name_list.append(srv["name"])
                continue
            if res:
                service_name_list.append(srv["name"])

        return service_name_list
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def create_schedule(config, params, days):
    """
    Create a schedule object for the given number of days from now
    """
    try:
        pa = PaloAltoCustom(config, params)
        pa.setupApiKey(params["username"], params["password"])

        beijing_tz = timezone(timedelta(hours=8))
        current_time = datetime.now(beijing_tz)

        # Calculate schedule dates
        start_time = current_time
        end_date = start_time + timedelta(days=days)
        # Set end time to 20:00 (8:00 PM)
        end_time = end_date.replace(hour=20, minute=0, second=0, microsecond=0)

        # Format schedule name
        schedule_name = f"fortisoar_sch_{end_time.strftime('%Y%m%d')}"

        # Format schedule string as YYYY/MM/DD@HH:MM-YYYY/MM/DD@HH:MM
        schedule_str = f"{start_time.strftime('%Y/%m/%d@%H:%M')}-{end_time.strftime('%Y/%m/%d@%H:%M')}"

        payload = {
            "entry": {
                "@name": schedule_name,
                "schedule-type": {"non-recurring": {"member": [schedule_str]}},
            }
        }

        payload = check_payload(payload)

        try:
            res = pa.make_rest_call(
                endpoint="/Objects/Schedules",
                method="POST",
                data=json.dumps(payload),
                params={"name": schedule_name},
            )
            logger.info(f"Schedule {schedule_name} created successfully")
            return schedule_name
        except Exception as err:
            logger.error("Failed to create schedule, error {0}".format(err))
            if "Object Not Unique" in str(err):
                # Schedule already exists, return the name
                logger.info(f"Schedule {schedule_name} already exists")
                return schedule_name
            raise

    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def create_security_rule_payload(params):

    payload = {
        "entry": {
            "@name": params.get("name"),
            "from": {"member": [params.get("from")] if params.get("from") else []},
            "to": {"member": [params.get("to")] if params.get("to") else []},
            "source": {
                "member": (params.get("source") if params.get("source") else [])
            },
            "destination": {
                "member": (
                    params.get("destination") if params.get("destination") else []
                )
            },
            "service": {
                "member": (params.get("service") if params.get("service") else [])
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

    if params.get("log_start"):
        payload["entry"]["log-start"] = params.get("log_start")
    if params.get("log_end"):
        payload["entry"]["log-end"] = params.get("log_end")
    if params.get("log_setting"):
        payload["entry"]["log-setting"] = params.get("log_setting")
    if params.get("profile_setting"):
        payload["entry"]["profile-setting"] = {
            "group": {"member": params.get("profile_setting").split(",")}
        }

    # Handle schedule parameter
    if params.get("schedule"):
        payload["entry"]["schedule"] = params.get("schedule")

    if params.get("attributes"):
        payload["entry"].update(params.get("attributes"))

    payload = check_payload(payload)
    logger.debug("Payload: {0}".format(payload))
    return payload


def create_security_rule(config, params):
    try:
        pa = PaloAltoCustom(config, params)
        pa.setupApiKey(params["username"], params["password"])

        # Handle schedule creation if schedule parameter is provided
        schedule_days = params.get("schedule")
        if schedule_days and isinstance(schedule_days, int) and schedule_days > 0:
            try:
                schedule_name = create_schedule(config, params, schedule_days)
                # Add the schedule name to params for payload creation
                params["schedule"] = schedule_name
                logger.info(
                    f"Schedule {schedule_name} will be used for the security rule"
                )
            except Exception as err:
                logger.error(f"Failed to create schedule: {err}")
                # Continue without schedule if creation fails
                params.pop("schedule", None)

        payload = create_security_rule_payload(params)
        try:
            res = pa.make_rest_call(
                endpoint="/Policies/SecurityRules",
                method="POST",
                data=json.dumps(payload),
                params={"name": params.get("name")},
            )
            return res
        except Exception as err:
            logger.error("Failed to create policy, error {0}".format(err))
            if "Object Not Unique" in str(err):
                raise ConnectorError("Policy already exists")

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


def rest_check_health(config):
    # try:
    #     obj = PaloAltoCustom(config)
    #     res = obj.make_rest_call(endpoint="/Policies/SecurityRules", params={})
    # except Exception as err:
    #     # err.args[0]["code"]  # request ok if type of err.args[0] is dict
    #     if "Not Authenticated" not in str(err):
    #         raise ConnectorError(str(err))
    return True


def commit_config(config, params):

    logger.debug("Committing the Request changes")
    try:

        pa = PaloAltoCustom(config, params)
        pa.setupApiKey(params["username"], params["password"])
        data = {
            "type": "commit",
            "cmd": "<commit></commit>",
            "key": pa._key,
        }
        res = requests.post(
            pa._server_url + "/api",
            data=data,
            verify=False,
        )
        if res.ok:
            return True
        else:
            logger.error(res.text)
            raise ConnectorError(res.text)
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


operations = {
    "create_security_rule": create_security_rule,
    "create_address": create_address,
    "get_address_details": get_address_details,
    "create_service": create_service,
    "create_schedule": create_schedule,
    "get_zone": get_zone,
    "get_ha_status": get_ha_status,
    "commit_config": commit_config,
}
