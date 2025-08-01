from ipaddress import ip_address, ip_network
from datetime import datetime, timedelta, timezone
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
    "ip": 0,
}


class Endpoint:
    # monitor_router_lookup = "router/lookup"
    get_ha_status = "system/ha-statistics/select/"
    address = "addrbook_address"
    service = "servicebook_service"
    policy = "policy_rule"
    zone = "api/zone"
    schedule = "schedule_schedule_list"


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
                    addr_name_list.append("Any")
                    continue
                mask = obj.netmask
                if str(mask) == "255.255.255.255":
                    name = f"Host_{str(net)}"
                    ip_addr = str(net)
                else:
                    name = f"Network_{str(net)}_{obj.prefixlen}"
                    ip_addr = str(net)

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
                                "ip_addr": ip_addr,
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


def create_schedule(client, schedule_days):
    """
    Create a schedule for temporary policy

    Args:
        client: HillStoneFWClient instance
        policy_name: Name of the policy
        schedule_days: Number of days the policy should be active

    Returns:
        str: Schedule name
    """
    try:
        # Get current time in Beijing timezone (UTC+8)
        beijing_tz = timezone(timedelta(hours=8))
        current_time = datetime.now(beijing_tz)

        # Calculate end time (current day + schedule_days, always at 20:00 Beijing time)
        end_time = current_time + timedelta(days=schedule_days)
        end_time = end_time.replace(hour=20, minute=0, second=0, microsecond=0)

        # Format end date as YYYYMMDD
        end_date_str = end_time.strftime("%Y%m%d")
        schedule_name = f"fortisoar_sch_{end_date_str}"

        schedule_data = [
            {
                "name": schedule_name,
                "type": "0",
                "schedule_periodic": [],
                "schedule_absolute": {
                    "start_time_mask": 1,
                    "start_year": current_time.year,
                    "start_month": current_time.month,
                    "start_day": current_time.day,
                    "start_hour": current_time.hour,
                    "start_minutes": current_time.minute,
                    "start_second": current_time.second,
                    "end_time_mask": 1,
                    "end_year": end_time.year,
                    "end_month": end_time.month,
                    "end_day": end_time.day,
                    "end_hour": end_time.hour,
                    "end_minutes": end_time.minute,
                    "end_second": end_time.second,
                },
                "schedule_description": {"description": f"created by fortisoar"},
            }
        ]

        # Create the schedule
        res = client.request(
            "POST", f"{Endpoint.schedule}?isTransaction=1", data=schedule_data
        )
        logger.info(f"Schedule created: {schedule_name}")
        logger.debug(f"Schedule creation response: {res.json()}")

        return schedule_name

    except Exception as err:
        logger.exception("Error creating schedule: {0}".format(err))
        raise ConnectorError("Error creating schedule: {0}".format(err))


def create_policy(config, params):
    # host = params.get("host")
    # vdom = params.get("vdom") if params.get("vdom") else None
    name = params.get("name")
    schedule_days = params.get("schedule")  # Number of days for temporary policy

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

    log_start = params.get("log_start")
    log_end = params.get("log_end")
    log_deny = params.get("log_deny")

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
            "log_start": "1" if log_start else "0",
            "log_end": "1" if log_end else "0",
            "log_deny": "1" if log_deny else "0",
        }
    ]

    try:
        config["url"] = params["host"]
        client = HillStoneFWClient(config, params["username"], params["password"])
        client.login()

        # If schedule_days is provided, create a schedule for temporary policy
        schedule_name = None
        if schedule_days and isinstance(schedule_days, int) and schedule_days > 0:
            try:
                schedule_name = create_schedule(client, schedule_days)
                # Add schedule to policy data
                data[0]["schedname"] = [{"name": schedule_name}]
                logger.info(
                    f"Policy {name} will use schedule {schedule_name} for {schedule_days} days"
                )
            except Exception as schedule_err:
                logger.warning(
                    f"Failed to create schedule for policy {name}: {schedule_err}"
                )
                # Continue without schedule if schedule creation fails

        res = client.request("POST", Endpoint.policy, data=data)

        result = res.json()
        if schedule_days:
            result["schedule_info"] = {
                "schedule_name": schedule_name,
                "schedule_days": schedule_days,
                "created_with_schedule": schedule_name is not None,
            }

        return result
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


def get_zone_by_interface(config, params):
    try:
        config["url"] = params["host"]
        vrouer = params.get("vrouter")
        interface_name = params.get("interface_name")
        client = HillStoneFWClient(config, params["username"], params["password"])
        client.login()
        res = client.request("GET", Endpoint.zone).json()
        # sample data
        # {
        #     "name": "untrust",
        #     "vr": "trust-vr",
        #     "shared": "0",
        #     "ztype": "0",
        #     "ident": "0",
        #     "wan_type": "1",
        #     "idp_direction": "0",
        #     "ad_profile": "1",
        #     "interface_list": [  ## this key is not always present
        #         "aggregate4"
        #     ]
        # }
        # filter the vr and interface_list and return the zone name
        if "success" in res and res["success"] is False:
            client.login(is_api_login=True)
            res = client.request("GET", Endpoint.zone).json()

        if "result" in res:
            for zone in res["result"]:
                if vrouer and zone["vr"] != vrouer:
                    continue
                if (
                    interface_name
                    and "interface_list" in zone
                    and interface_name in zone["interface_list"]
                ):
                    return zone["name"]

    except Exception as err:
        logger.exception("Error: {0}".format(err))
        raise ConnectorError("Error: {0}".format(err))


def get_vrouter(config, params):
    vrouter = config.get("vrouter")
    return vrouter


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
    "get_zone_by_interface": get_zone_by_interface,
    "get_vrouter": get_vrouter,
}
