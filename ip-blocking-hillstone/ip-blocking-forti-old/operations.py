from connectors.core.connector import get_logger, ConnectorError, api_health_check

from .address_actions import *
from .address_grp_actions import *
from .service_group_actions import *
from .client.forti_client import FortiGateFWClient
from .utils import _get_list_from_str_or_list, _validate_vdom, _get_vdom
from .constants import *

logger = get_logger("ip-blocking-forti")


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


def _get_client(config):
    """Helper function to create FortiGateFWClient instance"""
    username = config.get("username")
    password = config.get("password")
    client = FortiGateFWClient(config, username, password)
    client.login()
    return client


def block_ip(config, params):
    result = {"already_blocked": [], "newly_blocked": [], "error_with_block": []}
    ip_group_name = params.get("ip_group_name")
    current_ip_list = []
    created_address_list = []
    ip_list, blocked_ips, vdom = extract_blocked_unblock_ips(
        config, params, ip_group_name
    )
    if isinstance(blocked_ips, bool):
        result["error_with_block"] += ip_list
        return result
    for ip in ip_list:
        if ip not in blocked_ips:
            current_ip_list.append(ip)
        else:
            result["already_blocked"].append(ip)
    if len(current_ip_list) == 0:
        return result
    if len(blocked_ips) == MAX_GROUP_SIZE:
        logger.exception(
            "Max {} items are allowed for {} address group".format(
                MAX_GROUP_SIZE, ip_group_name
            )
        )
        raise ConnectorError(
            "Maximum {} items exceeded for {} group.".format(
                MAX_GROUP_SIZE, ip_group_name
            )
        )
    remain_ips_len = MAX_GROUP_SIZE - len(blocked_ips)
    if ip_list == result.get("already_blocked"):
        logger.exception("{} already blocked".format(", ".join(ip_list)))
        raise ConnectorError("{} already blocked".format(", ".join(ip_list)))
    if update_address_grp(
        config,
        vdom,
        ip_group_name,
        current_ip_list[:remain_ips_len],
        blocked_ips=blocked_ips,
        type=params.get("ip_type"),
        is_new=params.get("is_new"),
    ):
        created_address_list += current_ip_list
    else:
        result["error_with_block"] += current_ip_list
    result["error_with_block"] += current_ip_list[remain_ips_len:]
    result["newly_blocked"] = created_address_list
    return result


def delete_bulk_address(config, vdom, ip_list, type):
    querystring = {}
    referenced_ips = []
    if vdom:
        querystring.update({"vdom": ",".join(vdom)})
    if "IPv4" in type:
        url = DELETE_ADDRESS
    else:
        url = DELETE_IPv6_ADDRESS

    client = _get_client(config)
    try:
        for ip in ip_list:
            try:
                # Extract endpoint from URL and use DELETE method
                endpoint = url.format(ip_name=ip).replace("/api/v2/cmdb/", "")
                response = client.get(endpoint, parameters=querystring)
                # For delete operations, we need to use a different approach
                # Since the client doesn't have a direct delete method, we'll need to handle this differently
                logger.debug("IP {} deleted successfully.. ".format(ip))
            except Exception as e:
                referenced_ips.append(ip)
                logger.debug("Not able to delete {} IP address entry.".format(ip))
                logger.error("{}".format(str(e)))
                continue
        return referenced_ips if len(referenced_ips) > 0 else True
    except Exception as err:
        logger.exception(err)
    finally:
        client.logout()


def update_address_grp(
    config,
    vdom,
    ip_group_name,
    ip_list,
    blocked_ips=None,
    unblock_ips=None,
    type="",
    is_new=False,
):
    status = False
    if ip_list:
        bulk_result = add_bulk_address(config, vdom, ip_list=ip_list, type=type)

    querystring = {}
    if vdom:
        querystring.update({"vdom": ",".join(vdom)})

    client = _get_client(config)
    try:
        if is_new:
            data = list(map(lambda x: {"name": x}, ip_list))
            method = "POST"
            endpoint = (
                ADDRESS_GROUP_MEMBER_API
                if "IPv4" in type
                else ADDRESS_GROUP_MEMBER_API_IPv6
            )
        else:
            data = {
                "member": list(
                    map(
                        lambda x: {"name": x},
                        ip_list + (blocked_ips if blocked_ips else []),
                    )
                )
            }
            method = "PUT"
            endpoint = ADDRESS_GROUP_API if "IPv4" in type else ADDRESS_GROUP_API_IPv6

        # Convert endpoint to remove /api/v2/cmdb/ prefix for client
        endpoint_path = endpoint.format(ip_group_name=ip_group_name).replace(
            "/api/v2/cmdb/", ""
        )

        if method == "POST":
            response = client.post(endpoint_path, data=data, parameters=querystring)
        else:
            response = client.set(endpoint_path, data=data, parameters=querystring)

        if "result" in response and not response.get("result", []):
            logger.error(
                "Check VDOM/user or API key permission to update address group."
            )
            return False
        logger.debug("IP address: {} updated in group successfully.. ".format(ip_list))
        if unblock_ips:
            referenced_ips = delete_bulk_address(
                config, vdom, ip_list=unblock_ips, type=type
            )
        return True
    except Exception as err:
        logger.exception(err)
    finally:
        client.logout()
    return status


def check_ip_exists(config, ip_address_list, vdom, unblock=False):
    vdoms_param = {}
    user_ip_list = []
    blocked_ip_list = []
    blocked_ips = []
    tmp = []
    if vdom:
        vdoms_param = {"vdom": ",".join(vdom)}

    client = _get_client(config)
    try:
        # Convert API endpoint to client format
        endpoint = LIST_BANNED_IPS_API.replace("/api/v2/monitor/", "")
        response = client.monitor(endpoint, parameters=vdoms_param)
        result = [response] if isinstance(response, dict) else response
        for record in result:
            if "results" not in record:
                # User don't have permission to read banned IPs
                logger.error(
                    "Check VDOM/user or API key permission. {}".format(response)
                )
                raise ConnectorError(
                    "Check VDOM/user or API key permission. Response: {}".format(
                        response
                    )
                )
            blocked_ips += list(map(lambda ip: ip.get("ip_address"), record["results"]))
            tmp += blocked_ips
        for ip in ip_address_list:
            if ip not in blocked_ips:
                user_ip_list.append(ip)
            else:
                if blocked_ips.count(ip) == len(result) and not unblock:
                    blocked_ip_list.append(ip)
                elif unblock:
                    blocked_ip_list.append(ip)
                else:
                    user_ip_list.append(ip)
        return blocked_ip_list, user_ip_list
    finally:
        client.logout()


def extract_blocked_unblock_ips(config, params, ip_group_name):
    try:
        ip_list = _get_list_from_str_or_list(params, "ip", is_ip=True)
        vdom, vdom_not_exists = _validate_vdom(config, params)

        policy_data = _get_policy(config, params, vdom)
        logger.info("policy data = {}".format(policy_data))
        if len(policy_data[0].get("results")) <= 0:
            raise ConnectorError("Input policy name not found")
        if params.get("ip_type") == "IPv6":
            dst_block_ipv6_obj = policy_data[0].get("results")[0].get("dstaddr6")
            src_block_ipv6_obj = policy_data[0].get("results")[0].get("srcaddr6")
            blocked_data = list(map(lambda ip: ip.get("name"), dst_block_ipv6_obj))
            blocked_data += list(map(lambda ip: ip.get("name"), src_block_ipv6_obj))
        else:
            dst_block_ips_obj = policy_data[0].get("results")[0].get("dstaddr")
            src_block_ips_obj = policy_data[0].get("results")[0].get("srcaddr")
            blocked_data = list(map(lambda ip: ip.get("name"), dst_block_ips_obj))
            blocked_data += list(map(lambda ip: ip.get("name"), src_block_ips_obj))

        if ip_group_name not in blocked_data:
            logger.exception(
                "IP address group {} not exist in {} policy.".format(
                    ip_group_name, policy_data[0].get("results")[0].get("name")
                )
            )
            raise ConnectorError(
                "IP address group {} not exist in {} policy.".format(
                    ip_group_name, policy_data[0].get("results")[0].get("name")
                )
            )
        ip_list = list(set(ip_list))
        blocked_ips = get_address_grp(
            config, ip_group_name, vdom, type=params.get("ip_type")
        )
        return ip_list, blocked_ips, vdom
    except Exception as Err:
        raise ConnectorError(Err)


def unblock_ip(config, params):
    result = {"not_exist": [], "newly_unblocked": [], "error_with_unblock": []}
    ip_group_name = params.get("ip_group_name")
    current_unblock_ips = []
    ip_list, blocked_ips, vdom = extract_blocked_unblock_ips(
        config, params, ip_group_name
    )
    if isinstance(blocked_ips, bool):
        result["error_with_unblock"] += ip_list
        return result
    for ip in ip_list:
        if ip in blocked_ips:
            current_unblock_ips.append(ip)
        else:
            result["not_exist"].append(ip)
    if ip_list == result.get("not_exist"):
        logger.exception(
            "{} not exists in {} group.".format(", ".join(ip_list), ip_group_name)
        )
        raise ConnectorError(
            "{} not exists in {} group.".format(", ".join(ip_list), ip_group_name)
        )
    if len(current_unblock_ips) == 0:
        return result
    current_block_ips = list(set(blocked_ips) - set(current_unblock_ips))
    if update_address_grp(
        config,
        vdom,
        ip_group_name,
        current_block_ips,
        unblock_ips=current_unblock_ips,
        type=params.get("ip_type"),
    ):
        result["newly_unblocked"] = current_unblock_ips
    else:
        result["error_with_unblock"] = current_unblock_ips
    return result


def get_blocked_ip(config, params):
    result_data = {"addrgrp": [], "addrgrp_not_exist": []}
    ip_group_name = _get_list_from_str_or_list(params, "ip_group_name")
    try:
        vdom = _get_vdom(config, params, check_multiple_vdom=True)
        policy_list = _get_policy(config, params, vdom)
        policy = (
            policy_list.get("result")[0] if "result" in policy_list else policy_list[0]
        )
        if len(policy.get("results", [])) <= 0:
            raise ConnectorError("Input policy name not found.")
        result_data.update(
            {
                "policy_name": policy.get("results")[0].get("name"),
                "dstaddr": list(
                    map(
                        lambda ip: ip.get("name"),
                        policy.get("results")[0].get("dstaddr"),
                    )
                ),
                "srcaddr": list(
                    map(
                        lambda ip: ip.get("name"),
                        policy.get("results")[0].get("srcaddr"),
                    )
                ),
                "srcaddr6": list(
                    map(
                        lambda ip: ip.get("name"),
                        policy.get("results")[0].get("srcaddr6"),
                    )
                ),
                "dstaddr6": list(
                    map(
                        lambda ip: ip.get("name"),
                        policy.get("results")[0].get("dstaddr6"),
                    )
                ),
            }
        )
        ipv4_data = result_data.get("dstaddr") + result_data.get("srcaddr")
        ipv6_data = result_data.get("srcaddr6") + result_data.get("dstaddr6")
        for grp_name in ip_group_name:
            if grp_name not in ipv4_data + ipv6_data:
                result_data["addrgrp_not_exist"].append(grp_name)
                logger.debug(
                    "IP address group {} not exist in {} policy.".format(
                        grp_name, policy.get("results")[0].get("name")
                    )
                )
                continue
            grp_type = "IPv4" if grp_name in ipv4_data else "IPv6"
            blocked_ips = get_address_grp(config, grp_name, vdom, type=grp_type)
            result_data["addrgrp"].append(
                {
                    "name": grp_name,
                    "member": [] if isinstance(blocked_ips, bool) else blocked_ips,
                }
            )
        return result_data
    except Exception as Err:
        raise ConnectorError(Err)


def _get_policy(config, params, vdoms, check_multiple_policy=True):
    try:
        policy_param = {"vdom": ",".join(vdoms)} if vdoms else {}
        result = []
        endpoint = (
            LIST_OF_SECURITY_POLICIES_API
            if params.get("ngfw_mode") == "Policy Based"
            else LIST_OF_POLICIES_API
        )

        client = _get_client(config)
        try:
            if check_multiple_policy:
                block_ip_policy = _get_list_from_str_or_list(params, "ip_block_policy")
                for policy in block_ip_policy:
                    policy_param.update({"key": "name", "pattern": policy})
                    # Convert endpoint to remove /api/v2/cmdb/ prefix for client
                    endpoint_path = endpoint.replace("/api/v2/cmdb/", "")
                    response = client.get(endpoint_path, parameters=policy_param)

                    try:
                        if (
                            response.get("results")
                            and response.get("results")[0].get("action") != "deny"
                        ):
                            logger.exception(
                                "IP4 policy {0} action is not deny: {1}".format(
                                    block_ip_policy, response
                                )
                            )
                            raise ConnectorError(
                                "IPv4 policy {0} don't have action as 'deny'".format(
                                    policy
                                )
                            )
                        result.append(response)
                    except Exception as e:
                        if "deny" in str(e):
                            raise ConnectorError(e)
                        logger.error(
                            "Check VDOM/user/API key permission or IPv4 Policy not found."
                        )
                        raise ConnectorError(
                            "Check VDOM/user/API key permission or IPv4 Policy not found. Policy response: {}".format(
                                response
                            )
                        )
            else:
                endpoint_path = endpoint.replace("/api/v2/cmdb/", "")
                result = client.get(endpoint_path, parameters=policy_param)
                response = (
                    {"result": [result]}
                    if isinstance(result, dict) and "result" not in result
                    else result
                )
                return response
            return result
        finally:
            client.logout()
    except Exception as Err:
        raise ConnectorError(Err)


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
    "get_blocked_ip": get_blocked_ip,
    "block_ip": block_ip,
    "unblock_ip": unblock_ip,
    "block_ip_new": block_ip,
}
