from ipaddress import ip_address, ip_network
from datetime import datetime, timedelta
import time
from connectors.core.connector import get_logger, ConnectorError, api_health_check
from .client.forti_client import FortiGateFWClient

logger = get_logger("fortigate-fw")


class Endpoint:
    monitor_router_lookup = "router/lookup"
    get_ha_status = "system/ha-checksums"
    address = "firewall/address"
    service = "firewall.service/custom"
    policy = "firewall/policy"
    zone = "system/zone"
    schedule = "firewall.schedule/onetime"


def route_lookup(config, params):

    host = params.get("host")
    vdom = params.get("vdom") if params.get("vdom") else None

    query_ip = params.get("query_ip")
    # check if the query_ip is a valid IP address
    if not query_ip:
        raise ConnectorError("Query IP address is required")
    if query_ip == "any":
        test_ip = "0.0.0.0"
    else:
        try:
            test_ip = ip_network(query_ip, strict=False)
            test_ip = str(test_ip.network_address)
        except ValueError:
            raise ConnectorError(f"Invalid IP address: {query_ip}")

    path = f"{Endpoint.monitor_router_lookup}"

    try:
        client = FortiGateFWClient(config, params["username"], params["password"])
        client.login(host=host, vdom=vdom)
        parameters = {"destination": test_ip}
        response = client.monitor(path, parameters=parameters)
        if response.get("status") == "success":
            if response["results"].get("interface"):
                intf_name = response["results"]["interface"]
                lookup_params = {"filter": f"interface=={intf_name}"}
                path = "system/zone"
                zone_list = client.get(path)
                if zone_list.get("results") and len(zone_list["results"]) > 0:
                    for zone in zone_list["results"]:
                        zone_name = zone["name"]
                        for zone_interface in zone["interface"]:
                            if zone_interface["interface-name"] == intf_name:
                                response["results"]["interface"] = zone_name

        client.logout()
        return response
    except Exception as err:
        logger.exception("Error: {0}".format(err))
        raise ConnectorError("Error: {0}".format(err))


def check_node_status(result):
    # Check if "is_root_primary" is in result and its value is True
    if "is_root_primary" in result:
        return result["is_root_primary"]
    # Check if "is_root_master" is in result and its value == 1 return True else False
    elif "is_root_master" in result:
        return True if result["is_root_master"] == 1 else False
    # Return True we can not get ha status, use default node
    else:
        return True


def get_ha_status(config, params):

    host = params.get("host")
    vdom = params.get("vdom") if params.get("vdom") else None

    path = f"{Endpoint.get_ha_status}"

    try:
        client = FortiGateFWClient(config, params["username"], params["password"])
        client.login(host=host, vdom=vdom)
        response = client.monitor(path)
        current_node_sn = response.get("serial")
        results = response.get("results")
        if not results:
            # device is in standalone mode
            return True
        for result in results:
            if result.get("serial_no") == current_node_sn:
                return check_node_status(result)
            return False
        client.logout()
        return False
    except Exception as err:
        logger.exception("Error: {0}".format(err))
        raise ConnectorError("Error: {0}".format(err))


def create_address(config, params):
    host = params.get("host")
    vdom = params.get("vdom") if params.get("vdom") else None

    post_addresses = params.get("addresses")

    try:
        client = FortiGateFWClient(config, params["username"], params["password"])
        client.login(host=host, vdom=vdom)
        addr_name_list = []
        for addr in post_addresses:

            # if addr is ip network, set name is Network_{addr}
            if addr == "any":
                addr_name_list.append("all")
                continue
            try:
                obj = ip_network(addr, False)
                net = obj.network_address
                if str(net) == "0.0.0.0":
                    addr_name_list.append("all")
                    continue
                mask = obj.netmask
                if str(mask) == "255.255.255.255":
                    name = f"Host_{str(net)}"
                else:
                    name = f"Network_{str(net)}_{str(obj.prefixlen)}"

            except ValueError:
                logger.error("Invalid IP network", addr)
                continue

            url = f"{Endpoint.address}/{name}"
            check_addr = client.get(url)
            logger.debug("check_addr: %s", check_addr)
            if check_addr["http_status"] == 404:
                logger.info("Creating address: %s", name)
                data = {
                    "name": f"{name}",
                    "subnet": f"{str(net)} {str(mask)}",
                    "type": "ipmask",
                    "comment": "fortisoar",
                }
                client.set(Endpoint.address, data=data)
            addr_name_list.append(name)
        client.logout()
        return addr_name_list
    except Exception as err:
        logger.exception("Error: {0}".format(err))
        raise ConnectorError("Error: {0}".format(err))


def create_service(config, params):
    host = params.get("host")
    vdom = params.get("vdom") if params.get("vdom") else None

    port_list = params.get("port_list")
    protocol_list = params.get("protocol_list")

    # service_name_list = []
    # for port, protocol in zip(port_list, protocol_list):
    #     service_name_list.append(
    #         {"port": port, "protocol": protocol, "name": f"{protocol.upper()}_{port}"}
    #     )
    service_name_list = [
        {"port": port, "protocol": protocol, "name": f"{protocol.upper()}_{port}"}
        for port in port_list
        for protocol in protocol_list
    ]

    try:
        client = FortiGateFWClient(config, params["username"], params["password"])
        client.login(host=host, vdom=vdom)
        for s in service_name_list:
            if len(s["name"]) > 64:
                raise ConnectorError(
                    f"Service name {s['name']} is too long. Maximum length is 64 characters."
                )
            url = f"{Endpoint.service}/{s['name']}"
            check_service = client.get(url)
            logger.debug("check_service: %s", check_service)
            if check_service["http_status"] == 404:
                logger.info("Creating service: %s", s["port"])
                protocol = "TCP/UDP/SCTP"
                if s["protocol"].lower() == "ip":
                    protocol = "IP"
                if s["protocol"].lower() == "icmp":
                    protocol = "ICMP"

                data = {
                    "name": s["name"],
                    "protocol": protocol,
                    "tcp-portrange": (
                        str(s["port"]) if s["protocol"].lower() == "tcp" else ""
                    ),
                    "udp-portrange": (
                        str(s["port"]) if s["protocol"].lower() == "udp" else ""
                    ),
                    "comment": "fortisoar",
                }
                client.post(Endpoint.service, data=data)
        client.logout()
        return [s["name"] for s in service_name_list]
    except Exception as err:
        logger.exception("Error: {0}".format(err))
        raise ConnectorError("Error: {0}".format(err))


def create_schedule(client, schedule_days):
    """
    Create a one-time schedule for temporary policy
    Args:
        client: FortiGate client instance
        policy_name: Name of the policy to create schedule for
        schedule_days: Number of days the schedule should be active
    Returns:
        schedule_name: Name of the created schedule
    """
    # Get current time
    current_time = datetime.now()

    # Calculate end time (current day + schedule_days at 20:00 Beijing time UTC+8)
    end_time = current_time + timedelta(days=schedule_days)
    end_time = end_time.replace(hour=20, minute=0, second=0, microsecond=0)

    # Format end date as YYYYMMDD
    end_date_str = end_time.strftime("%Y%m%d")
    schedule_name = f"fortisoar_sch_{end_date_str}"

    # Calculate end time (current day + schedule_days at 20:00 Beijing time UTC+8)
    end_time = current_time + timedelta(days=schedule_days)
    end_time = end_time.replace(hour=20, minute=0, second=0, microsecond=0)

    # Convert Beijing time (UTC+8) to UTC for the API
    # Subtract 8 hours to convert from Beijing time to UTC
    end_time_utc = end_time - timedelta(hours=8)

    # Format start and end times for FortiGate API
    start_str = current_time.strftime("00:00 %Y/%m/%d")
    end_str = end_time.strftime("20:00 %Y/%m/%d")

    # Convert to UTC timestamps
    start_utc = time.mktime(current_time.timetuple())
    end_utc = time.mktime(end_time_utc.timetuple())

    schedule_data = {
        "name": schedule_name,
        "start": start_str,
        "start-utc": start_utc,
        "end": end_str,
        "end-utc": end_utc,
        "color": {"value": 0},
        "expiration-days": schedule_days,
        "fabric-object": "disable",
    }

    # Check if schedule already exists
    url = f"{Endpoint.schedule}/{schedule_name}"
    check_schedule = client.get(url)

    if check_schedule["http_status"] == 404:
        logger.info("Creating schedule: %s", schedule_name)
        client.post(Endpoint.schedule, data=schedule_data)
    else:
        logger.info("Schedule %s already exists, updating", schedule_name)
        client.put(url, data=schedule_data)

    return schedule_name


def create_policy(config, params):
    host = params.get("host")
    vdom = params.get("vdom") if params.get("vdom") else None

    # Handle schedule parameter for temporary policies
    schedule_param = params.get("schedule", "always")
    schedule_name = None
    client = None

    if isinstance(schedule_param, int):
        # If schedule is an integer, it represents days for temporary policy
        policy_name = params.get("name")
        if not policy_name:
            raise ConnectorError(
                "Policy name is required when creating scheduled policy"
            )

        try:
            client = FortiGateFWClient(config, params["username"], params["password"])
            client.login(host=host, vdom=vdom)

            # Create the schedule first
            schedule_name = create_schedule(client, schedule_param)

        except Exception as err:
            logger.exception("Error creating schedule: {0}".format(err))
            raise ConnectorError("Error creating schedule: {0}".format(err))
    elif schedule_param == "always":
        # Use default "always" schedule - no custom schedule needed
        schedule_name = "always"
    else:
        # For any other string value, treat as existing schedule name
        schedule_name = schedule_param

    policy_data = {
        "name": params.get("name"),
        "srcintf": [{"name": params.get("srcintf")}],
        "dstintf": [{"name": params.get("dstintf")}],
        "srcaddr": [{"name": item} for item in params.get("srcaddr")],
        "dstaddr": [{"name": item} for item in params.get("dstaddr")],
        "service": [{"name": item} for item in params.get("service")],
        "action": params.get("action"),
        "comments": params.get("comments") if params.get("comments") else "fortisoar",
        "logtraffic": params.get("logtraffic"),
    }

    # Add schedule to policy data
    if schedule_name == "always":
        # For "always" schedule, use string format
        policy_data["schedule"] = "always"
    elif schedule_name:
        # For custom schedules, use q_origin_key format
        policy_data["schedule"] = {"q_origin_key": schedule_name}
    else:
        # Fallback to always if no schedule specified
        policy_data["schedule"] = "always"

    try:
        if client is None:
            client = FortiGateFWClient(config, params["username"], params["password"])
            client.login(host=host, vdom=vdom)

        res = client.set(Endpoint.policy, data=policy_data)
        client.logout()
        return res
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


def _check_health(config):
    host, verify_ssl = get_config(config)
    logger.info("Fortigate Test Connectivity")
    endpoint = "{0}/logincheck".format(str(host))
    try:
        response = api_health_check(endpoint, method="GET", verify=verify_ssl)
        if response:
            logger.info("Forti-FW Connector Available")
            return True
        else:

            raise ConnectorError(
                "Status: {0}, Details: {1} ".format(
                    str(response.status_code), str(response.content)
                )
            )
    except Exception as err:
        logger.exception("{}".format(str(err)))
        if "Max retries exceeded" in str(err):
            logger.exception("host {0} is not known".format(host))
            raise ConnectorError("host {0} is not known".format(host))
        else:
            logger.exception("Exception occurred : {0}".format(err))
            raise ConnectorError("failure: {}".format(str(err)))


operations = {
    "route_lookup": route_lookup,
    "get_ha_status": get_ha_status,
    "create_address": create_address,
    "create_service": create_service,
    "create_policy": create_policy,
}
