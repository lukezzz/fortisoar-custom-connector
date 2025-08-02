from ipaddress import ip_address, ip_network
from connectors.core.connector import get_logger, ConnectorError, api_health_check
from .client.forti_client import FortiGateFWClient

logger = get_logger("fortigate-fw")


class Endpoint:
    monitor_router_lookup = "router/lookup"
    get_ha_status = "system/ha-checksums"
    address = "firewall/address"
    address_group = "firewall/addrgrp"
    address6 = "firewall/address6"
    address_group6 = "firewall/addrgrp6"
    zone = "system/zone"


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


def _create_address(config, host, vdom, addresses, username, password):
    """Internal function to create address objects"""

    try:
        client = FortiGateFWClient(config, username, password)
        client.login(host=host, vdom=vdom)
        addr_name_list = []
        for addr in addresses:

            # if addr is ip network, set name is Network_{addr}
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


def _is_ipv6_address(ip_string):
    """Helper function to detect if an IP address is IPv6"""
    try:
        addr = ip_address(ip_string.split('/')[0])  # Remove CIDR notation if present
        return addr.version == 6
    except ValueError:
        return False


def _create_address6(config, host, vdom, addresses, username, password):
    """Internal function to create IPv6 address objects"""
    
    try:
        client = FortiGateFWClient(config, username, password)
        client.login(host=host, vdom=vdom)
        addr_name_list = []
        for addr in addresses:
            # if addr is ipv6 network, set name is IPv6_{addr}
            try:
                obj = ip_network(addr, False)
                net = obj.network_address
                if str(net) == "::":
                    addr_name_list.append("all")
                    continue
                    
                if obj.prefixlen == 128:
                    name = f"IPv6_Host_{str(net)}"
                else:
                    name = f"IPv6_Network_{str(net)}_{str(obj.prefixlen)}"

            except ValueError:
                logger.error("Invalid IPv6 network", addr)
                continue

            url = f"{Endpoint.address6}/{name}"
            check_addr = client.get(url)
            logger.debug("check_addr (IPv6): %s", check_addr)
            if check_addr["http_status"] == 404:
                logger.info("Creating IPv6 address: %s", name)
                data = {
                    "name": f"{name}",
                    "ip6": f"{str(obj)}",
                    "color": "0",
                    "comment": "fortisoar",
                }
                client.set(Endpoint.address6, data=data)
            addr_name_list.append(name)
        client.logout()
        return addr_name_list
    except Exception as err:
        logger.exception("Error: {0}".format(err))
        raise ConnectorError("Error: {0}".format(err))


def get_blocked_ip(config, params):
    host = params.get("host")
    vdom = params.get("vdom") if params.get("vdom") else None

    ip_group_name = params.get("ip_group_name")

    try:
        client = FortiGateFWClient(config, params["username"], params["password"])
        client.login(host=host, vdom=vdom)
        if not ip_group_name:
            # Get all addresses
            url = f"{Endpoint.address}"
            response = client.get(url)
            if response["http_status"] != 200:
                raise ConnectorError(f"Failed to get addresses: {response}")
            addresses = response.get("results", [])
            blocked_ips = [
                addr["name"] for addr in addresses if addr.get("type") == "ipmask"
            ]
        else:
            # Get specific address group
            url = f"{Endpoint.address_group}/{ip_group_name}"
            response = client.get(url)
            if response["http_status"] == 404:
                raise ConnectorError(f"IP group {ip_group_name} not found")
            if response["http_status"] != 200:
                raise ConnectorError(
                    f"Failed to get IP group {ip_group_name}: {response}"
                )

            # Extract member names from address group
            results = response.get("results", [])
            if not results:
                blocked_ips = []
            else:
                # Get the first result (address group)
                address_group = results[0]
                members = address_group.get("member", [])
                blocked_ips = [member["name"] for member in members]

        client.logout()
        return blocked_ips
    except Exception as err:
        logger.exception("Error: {0}".format(err))
        raise ConnectorError("Error: {0}".format(err))


# block ip
def block_ip(config, params):
    host = params.get("host")
    vdom = params.get("vdom") if params.get("vdom") else None
    username = params.get("username")
    password = params.get("password")

    ip_group_name = params.get("ip_group_name")
    ip_address = params.get("ip_address")

    try:
        client = FortiGateFWClient(config, username, password)
        client.login(host=host, vdom=vdom)

        # Detect if the IP address is IPv6
        is_ipv6 = _is_ipv6_address(ip_address)
        
        # First, create the address object if it doesn't exist
        if is_ipv6:
            addr_name_list = _create_address6(
                config, host, vdom, [ip_address], username, password
            )
            address_group_endpoint = Endpoint.address_group6
        else:
            addr_name_list = _create_address(
                config, host, vdom, [ip_address], username, password
            )
            address_group_endpoint = Endpoint.address_group
            
        if not addr_name_list:
            raise ConnectorError(f"Failed to create address object for {ip_address}")

        addr_name = addr_name_list[0]

        # Check if the address group exists
        url = f"{address_group_endpoint}/{ip_group_name}"
        response = client.get(url)
        if response["http_status"] == 404:
            raise ConnectorError(f"IP group {ip_group_name} not found")
        if response["http_status"] != 200:
            raise ConnectorError(f"Failed to get IP group {ip_group_name}: {response}")

        # Get current members of the address group
        results = response.get("results", [])
        if not results:
            current_members = []
        else:
            address_group = results[0]
            current_members = address_group.get("member", [])

        # Check if address is already in the group
        existing_members = [member["name"] for member in current_members]
        if addr_name in existing_members:
            client.logout()
            return {
                "already_blocked": [ip_address],
                "newly_blocked": [],
                "error_with_block": [],
            }

        # Add the new address to existing members
        updated_members = current_members + [{"name": addr_name}]
        data = {"name": ip_group_name, "member": updated_members}

        # Update the address group with the new member
        update_response = client.set(
            f"{address_group_endpoint}/{ip_group_name}", data=data
        )

        client.logout()
        return {
            "already_blocked": [],
            "newly_blocked": [ip_address],
            "error_with_block": [],
        }
    except Exception as err:
        logger.exception("Error: {0}".format(err))
        return {
            "already_blocked": [],
            "newly_blocked": [],
            "error_with_block": [ip_address],
        }


# unblock ip
def unblock_ip(config, params):
    host = params.get("host")
    vdom = params.get("vdom") if params.get("vdom") else None
    username = params.get("username")
    password = params.get("password")

    ip_group_name = params.get("ip_group_name")
    ip_address = params.get("ip_address")

    try:
        client = FortiGateFWClient(config, username, password)
        client.login(host=host, vdom=vdom)

        # Detect if the IP address is IPv6
        is_ipv6 = _is_ipv6_address(ip_address)
        
        # Choose appropriate endpoint based on IP version
        if is_ipv6:
            address_group_endpoint = Endpoint.address_group6
        else:
            address_group_endpoint = Endpoint.address_group

        # Check if the address group exists
        url = f"{address_group_endpoint}/{ip_group_name}"
        response = client.get(url)
        if response["http_status"] == 404:
            raise ConnectorError(f"IP group {ip_group_name} not found")
        if response["http_status"] != 200:
            raise ConnectorError(f"Failed to get IP group {ip_group_name}: {response}")

        # Get current members of the address group
        results = response.get("results", [])
        if not results:
            raise ConnectorError(f"IP group {ip_group_name} is empty")

        address_group = results[0]
        current_members = address_group.get("member", [])

        # Check if address is in the group - create address name to match existing logic
        if is_ipv6:
            addr_name_list = _create_address6(
                config, host, vdom, [ip_address], username, password
            )
        else:
            addr_name_list = _create_address(
                config, host, vdom, [ip_address], username, password
            )
        addr_name = addr_name_list[0] if addr_name_list else None

        if not addr_name or addr_name not in [
            member["name"] for member in current_members
        ]:
            client.logout()
            return {
                "not_exist": [ip_address],
                "newly_unblocked": [],
                "error_with_unblock": [],
            }

        # Remove the address from the group
        updated_members = [
            member for member in current_members if member["name"] != addr_name
        ]
        data = {"name": ip_group_name, "member": updated_members}

        # Update the address group with the new members
        update_response = client.set(
            f"{address_group_endpoint}/{ip_group_name}", data=data
        )

        client.logout()
        return {
            "not_exist": [],
            "newly_unblocked": [ip_address],
            "error_with_unblock": [],
        }
    except Exception as err:
        logger.exception("Error: {0}".format(err))
        return {
            "not_exist": [],
            "newly_unblocked": [],
            "error_with_unblock": [ip_address],
        }


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
    "get_ha_status": get_ha_status,
    "get_blocked_ip": get_blocked_ip,
    "block_ip": block_ip,
    "unblock_ip": unblock_ip,
}
