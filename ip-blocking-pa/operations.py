from .connections import *
from .constants import ADDRESS_TYPE, ADDRESS_GROUP, POLICY_ACTION
from connectors.core.connector import ConnectorError, get_logger
from ipaddress import ip_address, ip_network
from xml.etree import ElementTree
import xmltodict


logger = get_logger("ip-blocking-pa")


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


def block_ip(config, params):
    """
    Block IP addresses by tagging them using XML API
    """
    # Initialize result structure
    result = {
        "already_blocked": [],
        "newly_blocked": [],
        "error_with_block": [],
        "error_message": "",
    }

    try:
        pa = PaloAltoCustom(config, params)
        pa.setupApiKey(params["username"], params["password"])

        ip_addresses = params.get("ip_addresses", [])
        tag_name = params.get("tag_name", "fortisoarBlocking")
        persistent = params.get("persistent", 1)
        timeout = params.get("timeout", 0)

        if not ip_addresses:
            result["error_message"] = "No IP addresses provided"
            return result

        # Ensure ip_addresses is a list
        if isinstance(ip_addresses, str):
            ip_addresses = [ip_addresses]

        # Build XML for IP registration
        entries = []
        for ip_addr in ip_addresses:
            # Validate IP address format
            try:
                ip_address(ip_addr)
            except ValueError:
                result["error_with_block"].append(
                    {"ip": ip_addr, "error": f"Invalid IP address format: {ip_addr}"}
                )
                continue

            entry = f'<entry ip="{ip_addr}" persistent="{persistent}"><tag><member timeout="{timeout}">{tag_name}</member></tag></entry>'
            entries.append(entry)

        # If no valid entries, return with errors
        if not entries:
            result["error_message"] = "No valid IP addresses to process"
            return result

        xml_cmd = f"""<uid-message>
            <type>update</type>
            <payload>
                <register>
                {''.join(entries)}
                </register>
            </payload>
            </uid-message>"""

        payload = {"type": "user-id", "key": pa._key, "cmd": xml_cmd}

        res_text = pa.make_xml_call(data=payload)
        response_dict = xmltodict.parse(res_text)

        if response_dict.get("response", {}).get("@status") == "success":
            # All IPs were successfully processed
            valid_ips = [
                ip
                for ip in ip_addresses
                if not any(error["ip"] == ip for error in result["error_with_block"])
            ]
            result["newly_blocked"] = valid_ips
            return result
        elif response_dict.get("response", {}).get("@status") == "error":
            # Parse error response to categorize IPs
            msg_content = (
                response_dict.get("response", {}).get("msg", {}).get("line", "")
            )

            logger.debug(f"Error response : {msg_content}")
            logger.debug(f"msg_content type: {type(msg_content)}")

            # Parse XML response to extract individual IP statuses
            try:
                register_entries = []

                # Handle case where msg_content is already parsed as OrderedDict
                if isinstance(msg_content, dict) and "uid-response" in msg_content:
                    register_entries = (
                        msg_content.get("uid-response", {})
                        .get("payload", {})
                        .get("register", {})
                        .get("entry", [])
                    )
                # Handle case where msg_content is a string containing XML
                elif isinstance(msg_content, str) and "<uid-response>" in msg_content:
                    # Extract uid-response XML
                    start_idx = msg_content.find("<uid-response>")
                    end_idx = msg_content.find("</uid-response>") + len(
                        "</uid-response>"
                    )
                    uid_xml = msg_content[start_idx:end_idx]

                    uid_dict = xmltodict.parse(uid_xml)
                    register_entries = (
                        uid_dict.get("uid-response", {})
                        .get("payload", {})
                        .get("register", {})
                        .get("entry", [])
                    )

                if register_entries:
                    # Ensure entries is a list
                    if not isinstance(register_entries, list):
                        register_entries = [register_entries]

                    for entry in register_entries:
                        ip_addr = entry.get("@ip")
                        message = entry.get("@message", "")

                        if "already exists, ignore" in message:
                            result["already_blocked"].append(ip_addr)
                        else:
                            result["error_with_block"].append(
                                {"ip": ip_addr, "error": message}
                            )
                else:
                    # If we can't parse the detailed response, mark remaining valid IPs as errors
                    valid_ips = [
                        ip
                        for ip in ip_addresses
                        if not any(
                            error["ip"] == ip for error in result["error_with_block"]
                        )
                    ]
                    for ip_addr in valid_ips:
                        result["error_with_block"].append(
                            {"ip": ip_addr, "error": "Unknown error"}
                        )

            except Exception as parse_err:
                logger.warning(f"Failed to parse error response: {parse_err}")
                # If parsing fails, mark remaining valid IPs as errors
                valid_ips = [
                    ip
                    for ip in ip_addresses
                    if not any(
                        error["ip"] == ip for error in result["error_with_block"]
                    )
                ]
                for ip_addr in valid_ips:
                    result["error_with_block"].append(
                        {"ip": ip_addr, "error": "Failed to parse response"}
                    )

            return result
        else:
            # Unexpected response status
            valid_ips = [
                ip
                for ip in ip_addresses
                if not any(error["ip"] == ip for error in result["error_with_block"])
            ]
            for ip_addr in valid_ips:
                result["error_with_block"].append(
                    {"ip": ip_addr, "error": "Unexpected response status"}
                )
            return result

    except Exception as err:
        logger.exception(str(err))
        result["error_message"] = str(err)
        return result


def unblock_ip(config, params):
    """
    Unblock IP addresses by removing tags using XML API
    """
    # Initialize result structure
    result = {
        "not_exist": [],
        "newly_unblocked": [],
        "error_with_unblock": [],
    }

    try:
        pa = PaloAltoCustom(config, params)
        pa.setupApiKey(params["username"], params["password"])

        ip_addresses = params.get("ip_addresses", [])
        tag_name = params.get("tag_name", "fortisoarBlocking")

        if not ip_addresses:
            result["error_with_unblock"] = ["No IP addresses provided"]
            return result

        # Ensure ip_addresses is a list
        if isinstance(ip_addresses, str):
            ip_addresses = [ip_addresses]

        # Build XML for IP unregistration
        entries = []
        for ip_addr in ip_addresses:
            # Validate IP address format
            try:
                ip_address(ip_addr)
            except ValueError:
                result["error_with_unblock"].append(ip_addr)
                continue

            entry = (
                f'<entry ip="{ip_addr}"><tag><member>{tag_name}</member></tag></entry>'
            )
            entries.append(entry)

        # If no valid entries, return with errors
        if not entries:
            return result

        xml_cmd = f"""<uid-message>
                <type>update</type>
                <payload>
                    <unregister>
                    {''.join(entries)}
                    </unregister>
                </payload>
                </uid-message>"""

        payload = {"type": "user-id", "key": pa._key, "cmd": xml_cmd}

        res_text = pa.make_xml_call(data=payload)
        response_dict = xmltodict.parse(res_text)

        if response_dict.get("response", {}).get("@status") == "success":
            # All valid IPs were successfully unblocked
            valid_ips = [
                ip
                for ip in ip_addresses
                if ip not in result["error_with_unblock"]
            ]
            result["newly_unblocked"] = valid_ips
            return result
        elif response_dict.get("response", {}).get("@status") == "error":
            # Parse error response to categorize IPs
            msg_content = (
                response_dict.get("response", {}).get("msg", {}).get("line", "")
            )

            logger.debug(f"Error response : {msg_content}")

            # Parse XML response to extract individual IP statuses
            try:
                unregister_entries = []

                # Handle case where msg_content is already parsed as OrderedDict
                if isinstance(msg_content, dict) and "uid-response" in msg_content:
                    unregister_entries = (
                        msg_content.get("uid-response", {})
                        .get("payload", {})
                        .get("unregister", {})
                        .get("entry", [])
                    )
                # Handle case where msg_content is a string containing XML
                elif isinstance(msg_content, str) and "<uid-response>" in msg_content:
                    # Extract uid-response XML
                    start_idx = msg_content.find("<uid-response>")
                    end_idx = msg_content.find("</uid-response>") + len(
                        "</uid-response>"
                    )
                    uid_xml = msg_content[start_idx:end_idx]

                    uid_dict = xmltodict.parse(uid_xml)
                    unregister_entries = (
                        uid_dict.get("uid-response", {})
                        .get("payload", {})
                        .get("unregister", {})
                        .get("entry", [])
                    )

                if unregister_entries:
                    # Ensure entries is a list
                    if not isinstance(unregister_entries, list):
                        unregister_entries = [unregister_entries]

                    for entry in unregister_entries:
                        ip_addr = entry.get("@ip")
                        message = entry.get("@message", "")

                        if "does not exist, ignore" in message or "not found" in message:
                            result["not_exist"].append(ip_addr)
                        elif "success" in message.lower():
                            result["newly_unblocked"].append(ip_addr)
                        else:
                            result["error_with_unblock"].append(ip_addr)
                else:
                    # If we can't parse the detailed response, mark remaining valid IPs as errors
                    valid_ips = [
                        ip
                        for ip in ip_addresses
                        if ip not in result["error_with_unblock"]
                    ]
                    result["error_with_unblock"].extend(valid_ips)

            except Exception as parse_err:
                logger.warning(f"Failed to parse error response: {parse_err}")
                # If parsing fails, mark remaining valid IPs as errors
                valid_ips = [
                    ip
                    for ip in ip_addresses
                    if ip not in result["error_with_unblock"]
                ]
                result["error_with_unblock"].extend(valid_ips)

            return result
        else:
            # Unexpected response status
            valid_ips = [
                ip
                for ip in ip_addresses
                if ip not in result["error_with_unblock"]
            ]
            result["error_with_unblock"].extend(valid_ips)
            return result

    except Exception as err:
        logger.exception(str(err))
        # Mark all remaining IPs as errors
        remaining_ips = [
            ip
            for ip in (ip_addresses if 'ip_addresses' in locals() else [])
            if ip not in result["error_with_unblock"]
        ]
        result["error_with_unblock"].extend(remaining_ips)
        return result


def get_dynamic_address_groups(config, params):
    """
    Get all Dynamic Address Groups from PA
    """
    try:
        pa = PaloAltoCustom(config, params)
        pa.setupApiKey(params["username"], params["password"])

        payload = {
            "type": "op",
            "key": pa._key,
            "cmd": "<show><object><dynamic-address-group><all></all></dynamic-address-group></object></show>",
        }

        res_text = pa.make_xml_call(data=payload)
        response_dict = xmltodict.parse(res_text)

        if response_dict.get("response", {}).get("@status") == "success":
            result = response_dict.get("response", {}).get("result", {})
            dyn_addr_grp = result.get("dyn-addr-grp", {})

            groups = []
            if dyn_addr_grp:
                entries = dyn_addr_grp.get("entry", [])
                if not isinstance(entries, list):
                    entries = [entries]

                for entry in entries:
                    group_info = {
                        "vsys": entry.get("vsys"),
                        "group_name": entry.get("group-name"),
                        "filter": entry.get("filter"),
                        "member_count": 0,
                        "members": [],
                    }

                    member_list = entry.get("member-list", {})
                    if member_list:
                        members = member_list.get("entry", [])
                        if not isinstance(members, list):
                            members = [members]

                        group_info["member_count"] = len(members)
                        group_info["members"] = [
                            {"name": member.get("@name"), "type": member.get("@type")}
                            for member in members
                        ]

                    groups.append(group_info)

            return {
                "status": "success",
                "message": f"Successfully retrieved {len(groups)} dynamic address group(s)",
                "groups": groups,
                "total_count": len(groups),
            }
        else:
            raise ConnectorError(f"Failed to get dynamic address groups: {res_text}")

    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def get_registered_ip(config, params):
    """
    Get all registered IP addresses from PaloAlto firewall
    """
    try:
        pa = PaloAltoCustom(config, params)
        pa.setupApiKey(params["username"], params["password"])

        payload = {
            "type": "op",
            "key": pa._key,
            "cmd": "<show><object><registered-ip><all></all></registered-ip></object></show>",
        }

        res_text = pa.make_xml_call(data=payload)
        response_dict = xmltodict.parse(res_text)

        if response_dict.get("response", {}).get("@status") == "success":
            result = response_dict.get("response", {}).get("result", {})

            registered_ips = []
            count = result.get("count", 0)

            # Handle both single entry and multiple entries
            entries = result.get("entry", [])
            if not isinstance(entries, list):
                entries = [entries] if entries else []

            for entry in entries:
                ip_info = {
                    "ip": entry.get("@ip"),
                    "from_agent": entry.get("@from_agent"),
                    "persistent": entry.get("@persistent"),
                    "tags": [],
                }

                # Extract tags
                tag_info = entry.get("tag", {})
                if tag_info:
                    members = tag_info.get("member", [])
                    if not isinstance(members, list):
                        members = [members]
                    ip_info["tags"] = members

                registered_ips.append(ip_info)

            return {
                "status": "success",
                "message": f"Successfully retrieved {len(registered_ips)} registered IP address(es)",
                "registered_ips": registered_ips,
                "total_count": count,
            }
        else:
            raise ConnectorError(f"Failed to get registered IP addresses: {res_text}")

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
    "block_ip": block_ip,
    "unblock_ip": unblock_ip,
    "get_dynamic_address_groups": get_dynamic_address_groups,
    "get_registered_ip": get_registered_ip,
    "get_ha_status": get_ha_status,
    "rest_check_health": rest_check_health,
}
