from ipaddress import ip_address, ip_network
from connectors.core.connector import get_logger, ConnectorError, api_health_check

from .utils import addr2dec
from .client.hs_client import HillStoneFWClient

logger = get_logger("hs-fw")

protocol_type_dict = {
    "Any": 0,
    "ICMP": 1,
    "IGMP": 2,
    "GGP": 3,
    "IPv4": 4,
    "ST": 5,
    "TCP": 6,
    "UDP": 17,
}


class Endpoint:
    # monitor_router_lookup = "router/lookup"
    get_ha_status = "system/ha-statistics/select/"
    address = "addrbook_address"
    service = "servicebook_service"
    policy = "policy_rule"


#
# def route_lookup(config, params):
#
#     host = params.get("host")
#     vdom = params.get("vdom") if params.get("vdom") else None
#
#     query_ip = params.get("query_ip")
#     # check if the query_ip is a valid IP address
#     try:
#         ip_address(query_ip)
#     except ValueError:
#         raise ConnectorError("Invalid IP address")
#
#     path = f"{Endpoint.monitor_router_lookup}"
#
#     try:
#         client = FortiGateFWClient(config, params["username"], params["password"])
#         client.login(host=host, vdom=vdom)
#         parameters = {"destination": query_ip}
#         response = client.monitor(path, parameters=parameters)
#         client.logout()
#         return response
#     except Exception as err:
#         logger.exception("Error: {0}".format(err))
#         raise ConnectorError("Error: {0}".format(err))


def create_address(config, params):
    post_addresses = params.get("addresses", [])

    try:
        config["url"] = params["host"]
        client = HillStoneFWClient(config, params["username"], params["password"])
        client.login()
        addr_name_list = []
        for addr in post_addresses:

            # if addr is ip network, set name is Network_{addr}
            try:
                obj = ip_network(addr, False)
                net = obj.network_address
                if str(net) == "0.0.0.0":
                    addr_name_list.append("All")
                    continue
                mask = obj.netmask
                if str(mask) == "255.255.255.255":
                    name = f"Host_{str(net)}"
                else:
                    name = f"Network_{str(net)}"

            except ValueError:
                logger.error("Invalid IP network", addr)
                continue

            check_addr = client.request("GET", Endpoint.address).json()
            logger.debug("check_addr: %s", check_addr)
            if check_addr["success"] and name not in {
                i["name"] for i in check_addr["result"]
            }:
                logger.info("Creating address: %s", name)
                # data = {
                #     "name": f"{name}",
                #     "subnet": f"{addr} {str(mask)}",
                #     "type": "ipmask",
                #     "comment": "fortisoar",
                # }
                data = [
                    {
                        "is_ipv6": 0,
                        "type": 0,
                        "name": name,
                        "description": "fortisoar",
                        "entry": [],
                        "ip": [
                            {
                                "ip_addr": addr2dec(addr),
                                "netmask": int(mask),
                                "flag": 0,
                            }
                        ],
                        "range": [],
                        "host": [],
                        "wildcard": [],
                        "country": [],
                    }
                ]
                client.request("POST", Endpoint.address, data=data)
            addr_name_list.append(name)
        return addr_name_list
    except Exception as err:
        logger.exception("Error: {0}".format(err))
        raise ConnectorError("Error: {0}".format(err))


def create_service(config, params):
    # host = params.get("host")
    # vdom = params.get("vdom") if params.get("vdom") else None

    port_list = params.get("port_list")
    protocol_list = params.get("protocol_list")
    # service_name_list = []
    # for port, protocol in zip(port_list, protocol_list):
    #     protocol = protocol.upper()
    #     service_name_list.append(
    #         {"port": port, "protocol": protocol, "name": f"{protocol}_{port}"}
    #     )
    service_name_list = [
        {
            "port": port,
            "protocol": protocol.upper(),
            "name": f"{protocol.upper()}_{port}",
        }
        for port in port_list
        for protocol in protocol_list
    ]
    try:
        config["url"] = params["host"]
        client = HillStoneFWClient(config, params["username"], params["password"])
        client.login()
        for s in service_name_list:
            if len(s["name"]) > 64:
                raise ConnectorError(
                    f"Service name {s['name']} is too long. Maximum length is 64 characters."
                )
            logger.info("Creating service: %s", s["port"])

            if s["protocol"] == "ICMP":
                data = [
                    {
                        "name": s["name"],
                        "type": "0",
                        "description": "fortisoar",
                        "row": "",
                        "icmp": [
                            {
                                "timeout": 0,
                                "icmpname": "3",
                                "code_min": "0",
                                "code_max": "15",
                            }
                        ],
                        "icmpv6": "",
                        "other_protocol": "",
                    }
                ]
            elif s["protocol"] == "ICMPV6":
                data = [
                    {
                        "name": s["name"],
                        "type": "0",
                        "description": "fortisoar",
                        "row": "",
                        "icmp": "",
                        "icmpv6": [
                            {
                                "timeout": 0,
                                "icmpname": "1",
                                "code_min": "0",
                                "code_max": "255",
                            }
                        ],
                        "other_protocol": "",
                    }
                ]
            else:
                data = [
                    {
                        "name": s["name"],
                        "type": "0",
                        "description": "",
                        "row": [
                            {
                                "timeout": 0,
                                "protocol": str(protocol_type_dict[s["protocol"]]),
                                "dp_low": str(s["port"]),
                                "dp_high": str(s["port"]),
                                "sp_low": "0",
                                "sp_high": "65535",
                            }
                        ],
                        "icmp": "",
                        "icmpv6": "",
                        "other_protocol": "",
                    }
                ]
            try:
                res = client.request("POST", Endpoint.service, data=data)
                logger.debug("Service created: %s", res.json())
            except Exception as err:
                logger.exception("Error: {0}".format(err))
                raise ConnectorError("Error: {0}".format(err))
        return [s["name"] for s in service_name_list]
    except Exception as err:
        logger.exception("Error: {0}".format(err))
        raise ConnectorError("Error: {0}".format(err))


def create_policy(config, params):
    # host = params.get("host")
    # vdom = params.get("vdom") if params.get("vdom") else None
    name = params.get("name")

    # policy_data = {
    #     "name": params.get("name"),
    #     "srcintf": [{"name": params.get("srcintf")}],
    #     "dstintf": [{"name": params.get("dstintf")}],
    #     "srcaddr": [{"name": item} for item in params.get("srcaddr")],
    #     "dstaddr": [{"name": item} for item in params.get("dstaddr")],
    #     "service": [{"name": item} for item in params.get("service")],
    #     "action": params.get("action"),
    #     "schedule": params.get("schedule"),
    #     "comments": params.get("comments") if params.get("comments") else "fortisoar",
    #     "logtraffic": params.get("logtraffic"),
    # }
    data = [
        {
            "id": -1,
            "name": {"name": name},
            "enable": 1,
            "src_zone": [{"name": params.get("srcintf")}],
            "src_addr": [
                {"member": item, "type": "0"} for item in params.get("srcaddr")
            ],
            "dst_zone": [{"name": params.get("dstintf")}],
            "dst_addr": [
                {"member": item, "type": "0"} for item in params.get("dstaddr")
            ],
            "service": [{"member": item} for item in params.get("service")],
            "icmp": [],
            "icmpv6": [],
            "description": {
                "content": (
                    params.get("comments") if params.get("comments") else "fortisoar"
                )
            },
            "action": "2",
        }
    ]

    try:
        config["url"] = params["host"]
        client = HillStoneFWClient(config, params["username"], params["password"])
        client.login()
        res = client.request("POST", Endpoint.policy, data=data)
        return res.json()
    except Exception as err:
        logger.exception("Error: {0}".format(err))
        raise ConnectorError("Error: {0}".format(err))


# operations default
def get_config(config):
    host = config.get("url")

    verify_ssl = config.get("verify_ssl")
    if all([host]):
        if not host.startswith("https://"):
            host = "https://" + host
        return host, verify_ssl
    else:
        logger.exception("Configuration field is required")
        raise ConnectorError("Configuration field is required")


def get_ha_status(config, params):
    try:
        config["url"] = params["host"]
        client = HillStoneFWClient(config, params["username"], params["password"])
        client.login()
        return client.get_admin_system_message()["ha_status"] == "Master"
    except Exception as err:
        logger.exception("Error: {0}".format(err))
        raise ConnectorError("Error: {0}".format(err))


def _check_health(config):
    # host, verify_ssl = get_config(config)
    # logger.info("Test Connectivity")
    # endpoint = "{0}/check_token_status".format(str(host))
    # try:
    #     response = api_health_check(endpoint, method="GET", verify=verify_ssl)
    #     if response:
    #         logger.info("HillStone-FW Connector Available")
    #         return True
    #     else:
    #         raise ConnectorError(
    #             "Status: {0}, Details: {1} ".format(
    #                 str(response.status_code), str(response.content)
    #             )
    #         )
    # except Exception as err:
    #     logger.exception("{}".format(str(err)))
    #     if "Max retries exceeded" in str(err):
    #         logger.exception("host {0} is not known".format(host))
    #         raise ConnectorError("host {0} is not known".format(host))
    #     else:
    #         logger.exception("Exception occurred : {0}".format(err))
    #         raise ConnectorError("failure: {}".format(str(err)))
    return True


operations = {
    "create_address": create_address,
    "create_service": create_service,
    "create_policy": create_policy,
    "get_ha_status": get_ha_status,
}
