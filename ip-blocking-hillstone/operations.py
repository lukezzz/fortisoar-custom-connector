from ipaddress import ip_address, ip_network
import json
import urllib.parse
from connectors.core.connector import get_logger, ConnectorError, api_health_check

from .utils import (
    _get_list_from_str_or_list,
    _validate_vsys,
)
from .client.hs_client import HillStoneFWClient
from .constants import *

logger = get_logger("ip-blocking-hillStone")


class Endpoint:
    # monitor_router_lookup = "router/lookup"
    get_ha_status = "system/ha-statistics/select/"
    address = ADDRESS_API
    service = SERVICE_API
    policy = POLICY_API
    zone = ZONE_API
    address_group = ADDRESS_API
    service_group = SERVICE_GROUP_API


def _is_ipv6_address(ip_string):
    """Helper function to detect if an IP address is IPv6"""
    try:
        addr = ip_address(ip_string.split("/")[0])  # Remove CIDR notation if present
        return addr.version == 6
    except ValueError:
        return False


def _get_client(config, params):
    """Helper function to create HillStoneFWClient instance"""
    config["url"] = params.get("host") or config.get("url")
    username = params.get("username") or config.get("username")
    password = params.get("password") or config.get("password")
    client = HillStoneFWClient(config, username, password)
    return client


def block_ip(config, params):
    """Block IP addresses by adding them to an address group"""
    result = {
        "already_blocked": [],
        "newly_blocked": [],
        "error_with_block": [],
        "error_message": "",
    }

    try:
        ip_list = _get_list_from_str_or_list(params, "ip_addresses", is_ip=True)
        group_name = params.get("group_name", "BlockedIPs")

        if not ip_list:
            return result

        client = _get_client(config, params)

        try:
            # Check if we should use old API
            if client.use_old_api:
                logger.debug("Using old API for blocking IPs")
                client.login(is_api_login=True)
                return _block_ip_old_api(client, group_name, ip_list)
            else:
                logger.debug("Using new API for blocking IPs")
                client.login()
                # Try to add each IP individually and handle "already exists" responses
                for ip in ip_list:
                    success, error_msg, is_already_added = _add_ip_to_address_group(
                        client, group_name, ip
                    )

                    if success:
                        result["newly_blocked"].append(ip)
                    elif is_already_added:
                        result["already_blocked"].append(ip)
                    else:
                        result["error_with_block"].append(
                            {"ip": ip, "error": error_msg or "Unknown error"}
                        )

        finally:
            pass
            # client.logout()

    except Exception as err:
        logger.exception(f"Error in block_ip: {err}")
        result["error_message"] = str(err)
        raise ConnectorError(f"Error blocking IPs: {err}")

    return result


def unblock_ip(config, params):
    """Unblock IP addresses by removing them from an address group"""
    result = {"not_exist": [], "newly_unblocked": [], "error_with_unblock": []}

    try:
        ip_list = _get_list_from_str_or_list(params, "ip_addresses", is_ip=True)
        group_name = params.get("group_name", "BlockedIPs")

        if not ip_list:
            return result

        client = _get_client(config, params)

        try:
            # Check if we should use old API
            if client.use_old_api:
                logger.debug("Using old API for unblocking IPs")
                client.login(is_api_login=True)
                return _unblock_ip_old_api(client, group_name, ip_list)
            else:
                logger.debug("Using new API for unblocking IPs")
                client.login()
                # Get existing address group
                existing_group = _get_address_group(client, group_name)
                if not existing_group:
                    result["not_exist"] = ip_list
                    return result

                existing_ips = []

                # Parse IPv4 list which now contains string IP addresses
                if existing_group.get("ip"):
                    for ip_entry in existing_group["ip"]:
                        if isinstance(ip_entry, dict) and "ip_addr" in ip_entry:
                            try:
                                # IP addresses are now stored as strings
                                ip_addr = ip_entry["ip_addr"]
                                netmask = ip_entry.get("netmask", "32")

                                # Format as CIDR notation if not /32
                                if netmask != "32":
                                    existing_ips.append(f"{ip_addr}/{netmask}")
                                else:
                                    existing_ips.append(ip_addr)
                            except (ValueError, TypeError) as e:
                                logger.warning(
                                    f"Failed to parse IPv4 {ip_entry.get('ip_addr')}: {e}"
                                )
                                continue

                # Parse IPv6 list
                if existing_group.get("ipv6"):
                    for ipv6_entry in existing_group["ipv6"]:
                        if isinstance(ipv6_entry, dict) and "ipv6_addr" in ipv6_entry:
                            try:
                                ipv6_addr = ipv6_entry["ipv6_addr"]
                                netmask = ipv6_entry.get("netmask", "128")
                                # Format as CIDR notation if not /128
                                if netmask != "128":
                                    existing_ips.append(f"{ipv6_addr}/{netmask}")
                                else:
                                    existing_ips.append(ipv6_addr)
                            except (ValueError, TypeError) as e:
                                logger.warning(
                                    f"Failed to parse IPv6 {ipv6_entry.get('ipv6_addr')}: {e}"
                                )
                                continue

                # Remove IPs from group using DELETE method for each IP
                for ip in ip_list:
                    if ip in existing_ips:
                        success, error_msg, not_in_group = (
                            _remove_ip_from_address_group(client, group_name, ip)
                        )
                        if success:
                            result["newly_unblocked"].append(ip)
                        elif not_in_group:
                            result["not_exist"].append(ip)
                        else:
                            result["error_with_unblock"].append(
                                {"ip": ip, "error": error_msg or "Unknown error"}
                            )
                    else:
                        result["not_exist"].append(ip)

        finally:
            # client.logout()
            pass

    except Exception as err:
        logger.exception(f"Error in unblock_ip: {err}")
        raise ConnectorError(f"Error unblocking IPs: {err}")

    return result


def get_blocked_ips(config, params):
    """Get list of blocked IP addresses from address groups"""
    result = {"groups": [], "error": []}

    try:
        group_names = _get_list_from_str_or_list(params, "group_names")
        if not group_names:
            group_names = ["BlockedIPs"]  # Default group name

        client = _get_client(config, params)

        try:
            # Check if we should use old API
            if client.use_old_api:
                logger.debug("Using old API for getting blocked IPs")
                client.login(is_api_login=True)
                for group_name in group_names:
                    group_info = {"name": group_name, "members": [], "ips": []}

                    existing_group, has_error = _get_address_group_old_api(
                        client, group_name
                    )
                    if has_error:
                        # API call failed, add to error list
                        result["error"].append(
                            f"Failed to retrieve group {group_name} from API"
                        )
                        continue

                    if existing_group:
                        # Parse IPv4 list
                        if existing_group.get("ip"):
                            for ip_entry in existing_group["ip"]:
                                if isinstance(ip_entry, dict) and "ip_addr" in ip_entry:
                                    try:
                                        ip_addr = ip_entry["ip_addr"]
                                        netmask = ip_entry.get("netmask", "32")

                                        if netmask != "32":
                                            ip_str = f"{ip_addr}/{netmask}"
                                        else:
                                            ip_str = ip_addr

                                        group_info["ips"].append(ip_str)
                                        group_info["members"].append(
                                            {
                                                "name": ip_str,
                                                "type": "address",
                                                "ip": ip_str,
                                            }
                                        )
                                    except (ValueError, TypeError) as e:
                                        logger.warning(
                                            f"Failed to parse IPv4 {ip_entry.get('ip_addr')}: {e}"
                                        )
                                        continue

                        result["groups"].append(group_info)
                    else:
                        result["error"].append(f"Group {group_name} not found")
            else:
                logger.debug("Using new API for getting blocked IPs")
                client.login()
                for group_name in group_names:
                    group_info = {"name": group_name, "members": [], "ips": []}

                    existing_group = _get_address_group(client, group_name)
                    if existing_group:
                        # Parse IPv4 list which now contains string IP addresses
                        if existing_group.get("ip"):
                            for ip_entry in existing_group["ip"]:
                                if isinstance(ip_entry, dict) and "ip_addr" in ip_entry:
                                    try:
                                        ip_addr = ip_entry["ip_addr"]
                                        netmask = ip_entry.get("netmask", "32")

                                        # Format as CIDR notation if not /32
                                        if netmask != "32":
                                            ip_str = f"{ip_addr}/{netmask}"
                                        else:
                                            ip_str = ip_addr

                                        group_info["ips"].append(ip_str)
                                        group_info["members"].append(
                                            {
                                                "name": ip_str,
                                                "type": "address",
                                                "ip": ip_str,
                                            }
                                        )
                                    except (ValueError, TypeError) as e:
                                        logger.warning(
                                            f"Failed to parse IPv4 {ip_entry.get('ip_addr')}: {e}"
                                        )
                                        continue

                        # Parse IPv6 list
                        if existing_group.get("ipv6"):
                            for ipv6_entry in existing_group["ipv6"]:
                                if (
                                    isinstance(ipv6_entry, dict)
                                    and "ipv6_addr" in ipv6_entry
                                ):
                                    try:
                                        ipv6_addr = ipv6_entry["ipv6_addr"]
                                        netmask = ipv6_entry.get("netmask", "128")
                                        # Format as CIDR notation if not /128
                                        if netmask != "128":
                                            ip_str = f"{ipv6_addr}/{netmask}"
                                        else:
                                            ip_str = ipv6_addr

                                        group_info["ips"].append(ip_str)
                                        group_info["members"].append(
                                            {
                                                "name": ip_str,
                                                "type": "address",
                                                "ip": ip_str,
                                            }
                                        )
                                    except (ValueError, TypeError) as e:
                                        logger.warning(
                                            f"Failed to parse IPv6 {ipv6_entry.get('ipv6_addr')}: {e}"
                                        )
                                        continue

                        result["groups"].append(group_info)
                    else:
                        result["error"].append(f"Group {group_name} not found")

        finally:
            # client.logout()
            pass

    except Exception as err:
        logger.exception(f"Error in get_blocked_ips: {err}")
        raise ConnectorError(f"Error getting blocked IPs: {err}")

    return result


def _get_address_group_old_api(client, group_name):
    """Get address group details using old REST API
    Returns: tuple (group_data, has_error)
        - group_data: group information if found, None if not found
        - has_error: True if API call failed, False if successful
    """
    try:
        # Build query parameters for address group lookup
        filter_str = {
            "conditions": [{"field": "name", "operator": 0, "value": group_name}]
        }
        params = {"query": json.dumps(filter_str)}

        endpoint = f"api/config/addrbook"
        response = client.request("GET", endpoint, parameters=params)

        logger.debug(f"Old API response from address group query: {response.json()}")
        if response.status_code == 200:
            data = response.json()
            if data.get("success") and data.get("result"):
                # Return the first matching group (should be exact match)
                for group in data.get("result", []):
                    if group.get("name") == group_name:
                        return group, False
                # Group not found but API call successful
                return None, False
            elif data.get("success") is False:
                # API returned error
                logger.error(
                    f"API returned error for address group {group_name}: {data}"
                )
                return None, True
        else:
            # HTTP error
            logger.error(
                f"HTTP error {response.status_code} getting address group {group_name}"
            )
            return None, True

        return None, False
    except Exception as err:
        logger.error(f"Error getting address group {group_name} with old API: {err}")
        return None, True


def _update_address_group_old_api(client, group_data):
    """Update address group using old REST API PUT method"""
    try:
        ip = client.host
        endpoint = "api/addrbook"

        response = client.request("PUT", endpoint, data=group_data)
        logger.debug(f"Old API update response: {response.json()}")

        if response.status_code == 200:
            result = response.json()
            return result.get("success", False), result.get("exception", {}).get(
                "message", ""
            )
        else:
            return False, f"HTTP {response.status_code}: {response.text}"
    except Exception as err:
        logger.error(f"Error updating address group with old API: {err}")
        return False, str(err)


def _block_ip_old_api(client, group_name, ip_list):
    """Block IPs using old API method"""
    result = {
        "already_blocked": [],
        "newly_blocked": [],
        "error_with_block": [],
        "error_message": "",
    }

    try:
        # Get current address book
        current_addrbook, has_error = _get_address_group_old_api(client, group_name)
        if has_error:
            # API call failed, raise error instead of proceeding
            error_msg = f"Failed to retrieve address group {group_name} from API"
            result["error_message"] = error_msg
            raise ConnectorError(error_msg)

        if not current_addrbook:
            # Create new address book if it doesn't exist
            current_addrbook = {
                "name": group_name,
                "is_ipv6": "0",
                "is_ordered": "0",
                "ip": [],
            }

        # Get existing IPs for comparison
        existing_ips = set()
        if current_addrbook.get("ip"):
            for ip_entry in current_addrbook["ip"]:
                if isinstance(ip_entry, dict) and "ip_addr" in ip_entry:
                    ip_addr = ip_entry["ip_addr"]
                    netmask = ip_entry.get("netmask", "32")
                    if netmask != "32":
                        existing_ips.add(f"{ip_addr}/{netmask}")
                    else:
                        existing_ips.add(ip_addr)

        # Process each IP to block
        new_addr_list = []
        for ip in ip_list:
            ip = ip.strip()
            if not ip:
                continue

            # Check if IP is already blocked
            if ip in existing_ips:
                result["already_blocked"].append(ip)
                continue

            # Determine if IP is IPv6
            is_ipv6 = _is_ipv6_address(ip)

            if is_ipv6:
                # Skip IPv6 for now as the old API structure focuses on IPv4
                result["error_with_block"].append(
                    {"ip": ip, "error": "IPv6 not supported in old API mode"}
                )
                continue

            try:
                # Validate and format IPv4 address
                ip_addr = ip_address(ip.split("/")[0])
                netmask = "32"
                if "/" in ip:
                    ip_net = ip_network(ip, False)
                    ip_str = str(ip_net.network_address)
                    netmask = str(ip_net.prefixlen)
                else:
                    ip_str = str(ip_addr)

                # Add to new address list
                new_addr_list.append({"ip_addr": ip_str, "netmask": netmask, "flag": 0})

            except ValueError as e:
                result["error_with_block"].append(
                    {"ip": ip, "error": f"Invalid IP address: {e}"}
                )
                continue

        # Extend current address book with new addresses
        if new_addr_list:
            if not current_addrbook.get("ip"):
                current_addrbook["ip"] = []
            current_addrbook["ip"].extend(new_addr_list)

            # Update the address book
            success, error_msg = _update_address_group_old_api(client, current_addrbook)
            if success:
                # Add all new IPs to newly_blocked
                for addr in new_addr_list:
                    ip_str = addr["ip_addr"]
                    if addr["netmask"] != "32":
                        ip_str = f"{ip_str}/{addr['netmask']}"
                    result["newly_blocked"].append(ip_str)
            else:
                # Add all attempted IPs to error list
                for addr in new_addr_list:
                    ip_str = addr["ip_addr"]
                    if addr["netmask"] != "32":
                        ip_str = f"{ip_str}/{addr['netmask']}"
                    result["error_with_block"].append(
                        {"ip": ip_str, "error": error_msg}
                    )

    except Exception as err:
        result["error_message"] = str(err)
        logger.error(f"Error in old API block_ip: {err}")

    return result


def _unblock_ip_old_api(client, group_name, ip_list):
    """Unblock IPs using old API method"""
    result = {"not_exist": [], "newly_unblocked": [], "error_with_unblock": []}

    try:
        # Get current address book
        current_addrbook, has_error = _get_address_group_old_api(client, group_name)
        if has_error:
            # API call failed, raise error instead of proceeding
            error_msg = f"Failed to retrieve address group {group_name} from API"
            raise ConnectorError(error_msg)

        if not current_addrbook or not current_addrbook.get("ip"):
            result["not_exist"] = ip_list
            return result

        # Create a mapping of existing IPs
        existing_ips = {}
        remaining_ips = []

        for ip_entry in current_addrbook["ip"]:
            if isinstance(ip_entry, dict) and "ip_addr" in ip_entry:
                ip_addr = ip_entry["ip_addr"]
                netmask = ip_entry.get("netmask", "32")
                if netmask != "32":
                    ip_key = f"{ip_addr}/{netmask}"
                else:
                    ip_key = ip_addr
                existing_ips[ip_key] = ip_entry
                remaining_ips.append(ip_entry)

        # Process each IP to unblock
        ips_to_remove = []
        for ip in ip_list:
            ip = ip.strip()
            if not ip:
                continue

            if ip in existing_ips:
                # Mark for removal
                ips_to_remove.append(existing_ips[ip])
                result["newly_unblocked"].append(ip)
            else:
                result["not_exist"].append(ip)

        # Remove IPs from the list
        if ips_to_remove:
            for ip_to_remove in ips_to_remove:
                if ip_to_remove in remaining_ips:
                    remaining_ips.remove(ip_to_remove)

            # Update the address book with remaining IPs
            current_addrbook["ip"] = remaining_ips
            success, error_msg = _update_address_group_old_api(client, current_addrbook)

            if not success:
                # Move newly_unblocked IPs to error list
                for ip in result["newly_unblocked"]:
                    result["error_with_unblock"].append({"ip": ip, "error": error_msg})
                result["newly_unblocked"] = []

    except Exception as err:
        logger.error(f"Error in old API unblock_ip: {err}")
        raise ConnectorError(f"Error unblocking IPs with old API: {err}")

    return result


def _get_address_group(client, group_name):
    """Get address group details using REST API"""
    try:
        # Build query parameters for address group lookup
        query_data = {"conditions": [{"field": "name", "value": group_name}]}

        # Build the URL with query parameters
        url = f"api/addrbook?query={json.dumps(query_data)}"

        response = client.request("GET", url)
        logger.debug(f"Response from address group query: {response.json()}")
        if response.status_code == 200:
            data = response.json()
            if data.get("success") and data.get("result"):
                # Return the first matching group (should be exact match)
                for group in data.get("result", []):
                    if group.get("name") == group_name:
                        return group
        return None
    except Exception as err:
        logger.error(f"Error getting address group {group_name}: {err}")
        return None


def _get_address_details(client, addr_name):
    """Get address object details"""
    try:
        response = client.request("GET", Endpoint.address)
        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                for addr in data.get("result", []):
                    if addr.get("name") == addr_name:
                        return addr
        return None
    except Exception as err:
        logger.error(f"Error getting address details {addr_name}: {err}")
        return None


def _add_ip_to_address_group(client, group_name, ip):
    """Add a single IP to address group and handle 'already exists' responses"""
    try:
        # Validate and format the IP address
        ip = ip.strip()
        if not ip:
            return False, "Empty IP address", False

        # Determine if IP is IPv6
        is_ipv6 = _is_ipv6_address(ip)

        # Prepare IP data structure
        if is_ipv6:
            # Handle IPv6 address
            try:
                if "/" in ip:
                    ipv6_net = ip_network(ip, False)
                    ipv6_addr = str(ipv6_net.network_address)
                    netmask = ipv6_net.prefixlen
                else:
                    ipv6_addr = ip
                    netmask = 128

                ip_data = {
                    "name": group_name,
                    "is_ipv6": "1",
                    "ipv6": [
                        {"ipv6_addr": ipv6_addr, "netmask": str(netmask), "flag": "0"}
                    ],
                    "predefined": "0",
                }
            except ValueError as e:
                return False, f"Invalid IPv6 address '{ip}': {e}", False
        else:
            # Handle IPv4 address
            try:
                ip_addr = ip_address(ip.split("/")[0])  # Remove CIDR if present
                netmask = "32"  # Default netmask for host addresses
                if "/" in ip:
                    # Handle CIDR notation
                    ip_net = ip_network(ip, False)
                    ip_str = str(ip_net.network_address)
                    netmask = str(ip_net.prefixlen)
                else:
                    ip_str = str(ip_addr)

                ip_data = {
                    "name": group_name,
                    "is_ipv6": "0",
                    "ip": [{"ip_addr": ip_str, "netmask": netmask, "flag": "0"}],
                    "predefined": "0",
                }
            except ValueError as e:
                return False, f"Invalid IPv4 address '{ip}': {e}", False

        logger.debug(f"Adding IP {ip} to group {group_name}: {ip_data}")
        # Make API call to add IP to group
        response = client.request("POST", "api/addrbook?nodeOption=1", data=[ip_data])

        if response.status_code == 200:
            result = response.json()
            logger.debug(f"Response from add IP to group: {result}")

            success = result.get("success", False)
            if success:
                return True, None, False
            else:
                # Check if the error indicates the IP is already in the group
                exception = result.get("exception", {})
                error_code = exception.get("code", "")
                error_message = exception.get("message", "")

                # Check for "already added" error
                if (
                    error_code == "400000002"
                    and "already added" in error_message.lower()
                ):
                    logger.debug(f"IP {ip} is already in group {group_name}")
                    return False, error_message, True
                else:
                    logger.error(
                        f"Failed to add IP {ip} to group {group_name}: {error_message}"
                    )
                    return False, error_message, False
        else:
            error_msg = f"HTTP {response.status_code}: {response.text}"
            logger.error(f"Failed to add IP {ip} to group {group_name}: {error_msg}")
            return False, error_msg, False

    except Exception as err:
        error_msg = str(err)
        logger.error(f"Error adding IP {ip_address} to group {group_name}: {error_msg}")
        return False, error_msg, False


def _remove_ip_from_address_group(client, group_name, ip_address):
    """Remove a single IP from address group using DELETE method"""
    try:
        # Validate and format the IP address
        ip = ip_address.strip()
        if not ip:
            return False, "Empty IP address", False

        # Determine if IP is IPv6
        is_ipv6 = _is_ipv6_address(ip)

        # Prepare IP data structure for DELETE request
        if is_ipv6:
            # Handle IPv6 address
            try:
                if "/" in ip:
                    ipv6_net = ip_network(ip, False)
                    ipv6_addr = str(ipv6_net.network_address)
                    netmask = ipv6_net.prefixlen
                else:
                    ipv6_addr = ip
                    netmask = 128

                ip_data = {
                    "name": group_name,
                    "is_ipv6": "1",
                    "ipv6": [
                        {"ipv6_addr": ipv6_addr, "netmask": str(netmask), "flag": "0"}
                    ],
                    "predefined": "0",
                }
            except ValueError as e:
                return False, f"Invalid IPv6 address '{ip}': {e}", False
        else:
            # Handle IPv4 address
            try:
                # Validate IP address format using the imported ip_address function
                from ipaddress import ip_address as validate_ip

                ip_addr = validate_ip(ip.split("/")[0])  # Remove CIDR if present
                netmask = "32"  # Default netmask for host addresses
                if "/" in ip:
                    # Handle CIDR notation
                    ip_net = ip_network(ip, False)
                    ip_str = str(ip_net.network_address)
                    netmask = str(ip_net.prefixlen)
                else:
                    ip_str = str(ip_addr)

                ip_data = {
                    "name": group_name,
                    "is_ipv6": "0",
                    "ip": [{"ip_addr": ip_str, "netmask": netmask, "flag": "0"}],
                    "predefined": "0",
                }
            except ValueError as e:
                return False, f"Invalid IPv4 address '{ip}': {e}", False

        logger.debug(f"Removing IP {ip} from group {group_name}: {ip_data}")

        # Make API call to remove IP from group using DELETE method
        response = client.request("DELETE", "api/addrbook?nodeOption=1", data=[ip_data])

        if response.status_code == 200:
            result = response.json()
            logger.debug(f"Response from remove IP from group: {result}")

            success = result.get("success", False)
            if success:
                return True, None, False
            else:
                # Check if the error indicates the IP is not in the group
                exception = result.get("exception", {})
                error_code = exception.get("code", "")
                error_message = exception.get("message", "")

                # Check for "no member" error (IP not in group)
                if (
                    error_code == "400000004"
                    and "has no member" in error_message.lower()
                ):
                    logger.debug(f"IP {ip} is not in group {group_name}")
                    return False, error_message, True
                else:
                    logger.error(
                        f"Failed to remove IP {ip} from group {group_name}: {error_message}"
                    )
                    return False, error_message, False
        else:
            error_msg = f"HTTP {response.status_code}: {response.text}"
            logger.error(
                f"Failed to remove IP {ip} from group {group_name}: {error_msg}"
            )
            return False, error_msg, False

    except Exception as err:
        error_msg = str(err)
        logger.error(
            f"Error removing IP {ip_address} from group {group_name}: {error_msg}"
        )
        return False, error_msg, False


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
    return True


operations = {
    "block_ip": block_ip,
    "unblock_ip": unblock_ip,
    "get_blocked_ips": get_blocked_ips,
    "get_vrouter": get_vrouter,
    "get_ha_status": get_ha_status,
}
