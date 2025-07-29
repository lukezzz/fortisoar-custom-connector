from ipaddress import ip_address, ip_network
import json
import urllib.parse
from connectors.core.connector import get_logger, ConnectorError, api_health_check

from .utils import (
    addr2dec,
    dec2addr,
    _get_list_from_str_or_list,
    _validate_vsys,
)
from .client.hs_client import HillStoneFWClient
from .constants import *

logger = get_logger("ip-blocking-hillStone")

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
    address = ADDRESS_API
    service = SERVICE_API
    policy = POLICY_API
    zone = ZONE_API
    address_group = ADDRESS_API
    service_group = SERVICE_GROUP_API


def _get_client(config, params):
    """Helper function to create HillStoneFWClient instance"""
    config["url"] = params.get("host") or config.get("url")
    username = params.get("username") or config.get("username")
    password = params.get("password") or config.get("password")
    client = HillStoneFWClient(config, username, password)
    client.login()
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
            # Get existing address group
            existing_group = _get_address_group(client, group_name)
            existing_ips = []

            if existing_group:
                # Extract existing IPs from group - Updated for new API format
                if existing_group.get("ip"):
                    # Parse IP list which contains decimal IP addresses
                    for ip_entry in existing_group["ip"]:
                        if isinstance(ip_entry, dict) and "ip_addr" in ip_entry:
                            try:
                                # Convert decimal IP back to string format
                                ip_decimal = ip_entry["ip_addr"]
                                # Handle both string and integer formats
                                if isinstance(ip_decimal, str):
                                    ip_decimal = int(ip_decimal)
                                ip_addr = dec2addr(ip_decimal)
                                existing_ips.append(ip_addr)
                            except (ValueError, TypeError) as e:
                                logger.warning(
                                    f"Failed to convert IP decimal {ip_entry.get('ip_addr')}: {e}"
                                )
                                continue

            # add new IPs
            new_ips = []
            for ip in ip_list:
                if ip in existing_ips:
                    result["already_blocked"].append(ip)
                else:
                    new_ips.append(ip)
                    result["newly_blocked"].append(ip)

            # Update address group (always update if we have IPs to block, even if they already exist)
            if result["newly_blocked"] or (not existing_group and existing_ips):
                success, error_msg = _update_address_group(
                    client, group_name, new_ips, existing_ips
                )
                if not success:
                    for ip_addr in new_ips:
                        result["error_with_block"].append(
                            {"ip": ip_addr, "error": error_msg or "Unknown error"}
                        )
                    result["newly_blocked"] = [
                        ip for ip in result["newly_blocked"] if ip not in new_ips
                    ]

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
            # Get existing address group
            existing_group = _get_address_group(client, group_name)
            if not existing_group:
                result["not_exist"] = ip_list
                return result

            existing_ips = []

            # Parse IP list which contains decimal IP addresses
            if existing_group.get("ip"):
                for ip_entry in existing_group["ip"]:
                    if isinstance(ip_entry, dict) and "ip_addr" in ip_entry:
                        try:
                            # Convert decimal IP back to string format
                            ip_decimal = ip_entry["ip_addr"]
                            # Handle both string and integer formats
                            if isinstance(ip_decimal, str):
                                ip_decimal = int(ip_decimal)
                            ip_addr = dec2addr(ip_decimal)
                            existing_ips.append(ip_addr)
                        except (ValueError, TypeError) as e:
                            logger.warning(
                                f"Failed to convert IP decimal {ip_entry.get('ip_addr')}: {e}"
                            )
                            continue

            # Remove IPs from group
            ips_to_remove = []
            for ip in ip_list:
                if ip in existing_ips:
                    ips_to_remove.append(ip)
                    result["newly_unblocked"].append(ip)
                else:
                    result["not_exist"].append(ip)

            # Update address group (remove IPs)
            if ips_to_remove:
                remaining_ips = [ip for ip in existing_ips if ip not in ips_to_remove]
                success, error_msg = _update_address_group(
                    client, group_name, [], remaining_ips, is_removal=True
                )
                if not success:
                    result["error_with_unblock"].extend(ips_to_remove)
                    result["newly_unblocked"] = [
                        ip
                        for ip in result["newly_unblocked"]
                        if ip not in ips_to_remove
                    ]

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
            for group_name in group_names:
                group_info = {"name": group_name, "members": [], "ips": []}

                existing_group = _get_address_group(client, group_name)
                if existing_group:
                    # Parse IP list which contains decimal IP addresses
                    if existing_group.get("ip"):
                        for ip_entry in existing_group["ip"]:
                            if isinstance(ip_entry, dict) and "ip_addr" in ip_entry:
                                try:
                                    # Convert decimal IP back to string format
                                    ip_decimal = ip_entry["ip_addr"]
                                    # Handle both string and integer formats
                                    if isinstance(ip_decimal, str):
                                        ip_decimal = int(ip_decimal)
                                    ip_addr = dec2addr(ip_decimal)
                                    group_info["ips"].append(ip_addr)
                                    # Add member info for compatibility
                                    member_info = {
                                        "name": f"addr_{ip_addr}",
                                        "ips": [ip_addr],
                                    }
                                    group_info["members"].append(member_info)
                                except (ValueError, TypeError) as e:
                                    logger.warning(
                                        f"Failed to convert IP decimal {ip_entry.get('ip_addr')}: {e}"
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


def _get_address_group(client, group_name):
    """Get address group details using dynamic query"""
    try:
        # Build query parameters for address group lookup
        query_data = {
            "fields": [],
            "conditions": [{"field": "name", "value": group_name}],
            "extraParams": {},
            "start": 0,
            "limit": 50,
            "page": 1,
        }

        # Encode the query parameters for the URL
        # query_params = {"isDynamic": "1", "query": json.dumps(query_data)}

        # Build the URL with query parameters
        # query_string = urllib.parse.urlencode(query_params)
        url = f"{Endpoint.address_group}?isTransaction=1&query={json.dumps(query_data)}"

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


def _update_address_group(client, group_name, new_ips, existing_ips, is_removal=False):
    """Update address group with new IPs using direct IP list format"""
    # Combine all IPs based on operation type
    if is_removal:
        # For removal, use only the remaining IPs (existing_ips contains the remaining ones)
        all_ips = existing_ips
    else:
        # For addition, combine existing and new IPs
        all_ips = existing_ips + new_ips

    # Convert IP addresses to the required format
    ip_list = []
    for ip in all_ips:
        try:
            # Skip empty or None IPs
            if not ip or not isinstance(ip, str):
                logger.warning(f"Skipping invalid IP: {ip}")
                continue

            # Strip whitespace
            ip = ip.strip()
            if not ip:
                logger.warning(f"Skipping empty IP after stripping whitespace")
                continue

            ip_decimal = addr2dec(ip)
            ip_list.append({"ip_addr": ip_decimal, "netmask": 32, "flag": 0})
            logger.debug(f"Converted IP {ip} to decimal: {ip_decimal}")
        except ValueError as e:
            logger.warning(f"Skipping invalid IP '{ip}': {e}")
            continue
        except Exception as e:
            logger.error(f"Unexpected error converting IP '{ip}': {e}")
            continue

    logger.debug(f"Updating address group {group_name} with IPs: {ip_list}")

    # Check if we have any valid IPs to process
    if not ip_list:
        if all_ips:
            error_msg = f"No valid IPs found in the list: {all_ips}"
            logger.error(error_msg)
            return False, error_msg
        else:
            # This is the case where we're removing all IPs from the group
            logger.info(f"Removing all IPs from address group {group_name}")

    try:
        # Prepare data in the required format
        data = [
            {
                "is_ipv6": 0,
                "type": 0,
                "name": group_name,
                "description": "IP Blocking Group - Updated by FortiSOAR",
                "entry": [],
                "ip": ip_list,
                "range": [],
                "host": [],
                "wildcard": [],
                "country": [],
            }
        ]

        # Always use PUT request
        response = client.request("PUT", Endpoint.address_group, data=data)

        if response.status_code == 200:
            result = response.json()
            success = result.get("success", False)
            if success:
                return True, None
            else:
                error_msg = result.get("message", "API returned success=false")
                logger.error(
                    f"Failed to update address group {group_name}: {error_msg}"
                )
                return False, error_msg
        else:
            error_msg = f"HTTP {response.status_code}: {response.text}"
            logger.error(f"Failed to update address group {group_name}: {error_msg}")
            return False, error_msg

    except Exception as err:
        error_msg = str(err)
        logger.error(f"Error updating address group {group_name}: {error_msg}")
        return False, error_msg


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
