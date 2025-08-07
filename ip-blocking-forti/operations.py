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
        addr = ip_address(ip_string.split("/")[0])  # Remove CIDR notation if present
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


def _get_child_groups(client, parent_group_name, is_ipv6=False):
    """Get all child groups for a parent group"""
    endpoint = Endpoint.address_group6 if is_ipv6 else Endpoint.address_group
    child_groups = []

    # Try to find child groups with pattern {parent_group_name}_1, {parent_group_name}_2, etc.
    i = 1
    while True:
        child_group_name = f"{parent_group_name}_{i}"
        url = f"{endpoint}/{child_group_name}"
        response = client.get(url)

        if response["http_status"] == 404:
            break  # No more child groups found
        elif response["http_status"] == 200:
            child_groups.append(child_group_name)
            i += 1
        else:
            logger.warning(
                f"Unexpected response when checking child group {child_group_name}: {response}"
            )
            break

    return child_groups


def _get_available_child_group(
    client, parent_group_name, max_ip_per_group, is_ipv6=False
):
    """Find an available child group that has space for more IPs, or create a new one"""
    endpoint = Endpoint.address_group6 if is_ipv6 else Endpoint.address_group
    child_groups = _get_child_groups(client, parent_group_name, is_ipv6)

    # Check existing child groups for available space
    for child_group_name in child_groups:
        url = f"{endpoint}/{child_group_name}"
        response = client.get(url)

        if response["http_status"] == 200:
            results = response.get("results", [])
            if results:
                current_members = results[0].get("member", [])
                if len(current_members) < max_ip_per_group:
                    return child_group_name, current_members

    # Create a new child group
    new_child_index = len(child_groups) + 1
    new_child_name = f"{parent_group_name}_{new_child_index}"

    # Create the new child group
    data = {
        "name": new_child_name,
        "type": "default",
        "comment": "fortisoar auto-created child group",
    }

    create_response = client.post(endpoint, data=data)
    if create_response["http_status"] not in [200, 201]:
        raise ConnectorError(
            f"Failed to create child group {new_child_name}: {create_response}"
        )

    logger.info(f"Created new child group: {new_child_name}")

    # Add the new child group to the parent group
    _add_child_to_parent_group(client, parent_group_name, new_child_name, is_ipv6)

    return new_child_name, []


def _add_child_to_parent_group(
    client, parent_group_name, child_group_name, is_ipv6=False
):
    """Add a child group to the parent group"""
    endpoint = Endpoint.address_group6 if is_ipv6 else Endpoint.address_group

    # Get current parent group
    url = f"{endpoint}/{parent_group_name}"
    response = client.get(url)

    if response["http_status"] == 404:
        # Create parent group if it doesn't exist
        data = {
            "name": parent_group_name,
            "type": "default",
            "member": [{"name": child_group_name}],
            "comment": "fortisoar parent group",
        }
        create_response = client.post(endpoint, data=data)
        if create_response["http_status"] not in [200, 201]:
            raise ConnectorError(
                f"Failed to create parent group {parent_group_name}: {create_response}"
            )
        logger.info(f"Created new parent group: {parent_group_name}")
    elif response["http_status"] == 200:
        # Add child to existing parent group
        results = response.get("results", [])
        if results:
            parent_group = results[0]
            current_members = parent_group.get("member", [])

            # Check if child group is already a member
            existing_members = [member["name"] for member in current_members]
            if child_group_name not in existing_members:
                updated_members = current_members + [{"name": child_group_name}]

                data = {
                    "name": parent_group_name,
                    "type": parent_group.get("type", "default"),
                    "member": updated_members,
                }

                update_response = client.set(
                    f"{endpoint}/{parent_group_name}", data=data
                )
                if update_response["http_status"] not in [200, 201]:
                    raise ConnectorError(
                        f"Failed to update parent group {parent_group_name}: {update_response}"
                    )
                logger.info(
                    f"Added child group {child_group_name} to parent group {parent_group_name}"
                )
    else:
        raise ConnectorError(
            f"Failed to get parent group {parent_group_name}: {response}"
        )


def _find_ip_in_child_groups(client, parent_group_name, addr_name, is_ipv6=False):
    """Find which child group contains the specified IP address"""
    endpoint = Endpoint.address_group6 if is_ipv6 else Endpoint.address_group
    child_groups = _get_child_groups(client, parent_group_name, is_ipv6)

    for child_group_name in child_groups:
        url = f"{endpoint}/{child_group_name}"
        response = client.get(url)

        if response["http_status"] == 200:
            results = response.get("results", [])
            if results:
                current_members = results[0].get("member", [])
                existing_members = [member["name"] for member in current_members]
                if addr_name in existing_members:
                    return child_group_name, current_members

    return None, []


def _get_all_blocked_ips_from_child_groups(client, parent_group_name, is_ipv6=False):
    """Get all blocked IPs from all child groups"""
    endpoint = Endpoint.address_group6 if is_ipv6 else Endpoint.address_group
    child_groups = _get_child_groups(client, parent_group_name, is_ipv6)
    all_blocked_ips = []

    for child_group_name in child_groups:
        url = f"{endpoint}/{child_group_name}"
        response = client.get(url)

        if response["http_status"] == 200:
            results = response.get("results", [])
            if results:
                current_members = results[0].get("member", [])
                blocked_ips = [member["name"] for member in current_members]
                all_blocked_ips.extend(blocked_ips)

    return all_blocked_ips


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
            # Check if parent group exists
            url = f"{Endpoint.address_group}/{ip_group_name}"
            response = client.get(url)

            if response["http_status"] == 404:
                # Try IPv6 groups
                url = f"{Endpoint.address_group6}/{ip_group_name}"
                response = client.get(url)
                if response["http_status"] == 404:
                    raise ConnectorError(f"IP group {ip_group_name} not found")
                is_ipv6 = True
            else:
                is_ipv6 = False

            if response["http_status"] != 200:
                raise ConnectorError(
                    f"Failed to get IP group {ip_group_name}: {response}"
                )

            # Get all blocked IPs from child groups
            blocked_ips = _get_all_blocked_ips_from_child_groups(
                client, ip_group_name, is_ipv6
            )

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
    max_ip_per_group = params.get(
        "max_ip_per_group", 500
    )  # Default to 500 if not specified

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
        else:
            addr_name_list = _create_address(
                config, host, vdom, [ip_address], username, password
            )

        if not addr_name_list:
            raise ConnectorError(f"Failed to create address object for {ip_address}")

        addr_name = addr_name_list[0]

        # Check if the IP is already blocked in any child group
        child_group_name, current_members = _find_ip_in_child_groups(
            client, ip_group_name, addr_name, is_ipv6
        )
        if child_group_name:
            client.logout()
            return {
                "already_blocked": [ip_address],
                "newly_blocked": [],
                "error_with_block": [],
            }

        # Find an available child group or create a new one
        available_child_group, current_members = _get_available_child_group(
            client, ip_group_name, max_ip_per_group, is_ipv6
        )

        # Add the new address to the child group
        updated_members = current_members + [{"name": addr_name}]

        endpoint = Endpoint.address_group6 if is_ipv6 else Endpoint.address_group

        # Get the current child group details to preserve other fields
        url = f"{endpoint}/{available_child_group}"
        response = client.get(url)
        if response["http_status"] != 200:
            raise ConnectorError(
                f"Failed to get child group {available_child_group}: {response}"
            )

        child_group_details = response.get("results", [{}])[0]

        data = {
            "name": available_child_group,
            "type": child_group_details.get("type", "default"),
            "member": updated_members,
            "comment": child_group_details.get(
                "comment", "fortisoar auto-created child group"
            ),
        }

        # Update the child group with the new member
        update_response = client.set(f"{endpoint}/{available_child_group}", data=data)
        if update_response["http_status"] not in [200, 201]:
            raise ConnectorError(
                f"Failed to update child group {available_child_group}: {update_response}"
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

        # Create address name to match existing logic
        if is_ipv6:
            addr_name_list = _create_address6(
                config, host, vdom, [ip_address], username, password
            )
        else:
            addr_name_list = _create_address(
                config, host, vdom, [ip_address], username, password
            )

        if not addr_name_list:
            client.logout()
            return {
                "not_exist": [ip_address],
                "newly_unblocked": [],
                "error_with_unblock": [],
            }

        addr_name = addr_name_list[0]

        # Find which child group contains the IP
        child_group_name, current_members = _find_ip_in_child_groups(
            client, ip_group_name, addr_name, is_ipv6
        )

        if not child_group_name:
            client.logout()
            return {
                "not_exist": [ip_address],
                "newly_unblocked": [],
                "error_with_unblock": [],
            }

        # Remove the address from the child group
        updated_members = [
            member for member in current_members if member["name"] != addr_name
        ]

        endpoint = Endpoint.address_group6 if is_ipv6 else Endpoint.address_group

        # Get the current child group details to preserve other fields
        url = f"{endpoint}/{child_group_name}"
        response = client.get(url)
        if response["http_status"] != 200:
            raise ConnectorError(
                f"Failed to get child group {child_group_name}: {response}"
            )

        child_group_details = response.get("results", [{}])[0]

        data = {
            "name": child_group_name,
            "type": child_group_details.get("type", "default"),
            "category": child_group_details.get("category", "default"),
            "uuid": child_group_details.get(
                "uuid", "00000000-0000-0000-0000-000000000000"
            ),
            "member": updated_members,
            "comment": child_group_details.get(
                "comment", "fortisoar auto-created child group"
            ),
            "exclude": child_group_details.get("exclude", "disable"),
            "exclude-member": child_group_details.get("exclude-member", []),
            "color": child_group_details.get("color", "0"),
            "tagging": child_group_details.get("tagging", []),
            "allow-routing": child_group_details.get("allow-routing", "disable"),
            "fabric-object": child_group_details.get("fabric-object", "disable"),
        }

        # Update the child group with the new members (without the removed IP)
        update_response = client.set(f"{endpoint}/{child_group_name}", data=data)
        if update_response["http_status"] not in [200, 201]:
            raise ConnectorError(
                f"Failed to update child group {child_group_name}: {update_response}"
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
