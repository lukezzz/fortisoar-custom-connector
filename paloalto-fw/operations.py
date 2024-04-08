from .connections import *
from .constants import ADDRESS_TYPE, ADDRESS_GROUP, POLICY_ACTION
from connectors.core.connector import ConnectorError, get_logger
from ipaddress import ip_address, ip_network

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


def create_payload(params):
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
    if params.get("attributes"):
        payload["entry"].update(params.get("attributes"))
    payload = check_payload(payload)
    return payload


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
                mask = obj.prefixlen
                if mask == 32:
                    name = f"Host_{str(net)}"
                else:
                    name = f"Network_{str(net)}"

            except ValueError:
                logger.error("Invalid IP network", addr)
                continue

            payload = {
                "entry": {
                    "@name": name,
                    "description": "fortisoar",
                    "ip-netmask": f"{addr}/{mask}",
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
        service_list = []
        for port, protocol in zip(port_list, protocol_list):
            service_list.append(
                {
                    "port": port,
                    "protocol": protocol,
                    "name": f"{protocol.upper()}_{port}",
                }
            )
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


def create_security_rule(config, params):
    try:
        pa = PaloAltoCustom(config, params)
        pa.setupApiKey(params["username"], params["password"])

        payload = create_payload(params)
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


operations = {
    "create_security_rule": create_security_rule,
    "create_address": create_address,
    "get_address_details": get_address_details,
    "create_service": create_service,
    "create_security_rule": create_security_rule,
}
