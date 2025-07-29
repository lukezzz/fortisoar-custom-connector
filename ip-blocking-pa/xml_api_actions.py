from .constants import *
from .connections import *
from connectors.core.connector import ConnectorError, get_logger
from ipaddress import ip_address
import xmltodict

logger = get_logger("paloalto-firewall")


def __add_ip_address(obj: PaloAltoCustom, ip):
    try:
        ip_xpath = IP_ADDRESS_XPATH.format(
            vsys_name=obj._virtual_sys, address_name=ip.replace("/", "-")
        )
        element = "<{ip_type}>{ip}</{ip_type}>".format(ip_type="ip-netmask", ip=ip)
        try:
            obj.make_request(action="set", xpath=ip_xpath, element=element)
        except Exception as exp:
            logger.debug("Failed to add IP address: {0}".format(str(exp)))
            raise ConnectorError("Failed to add IP address: {0}".format(str(exp)))
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def __add_address_to_group(obj, ip):
    element = "<static><member>{addr_name}</member></static>".format(addr_name=ip)
    try:
        obj.make_request(
            action="set",
            xpath=IP_XPATH_GROUP.format(
                vsys_name=obj._virtual_sys, address_group=obj._address_group
            ),
            element=element,
        )
    except Exception as exp:
        logger.debug("Failed to add Address to Address Group: {0}".format(str(exp)))
        raise ConnectorError(
            "Failed to add Address to Address Group: {0}".format(str(exp))
        )


def block_ip(config, params):
    """
    Block IP addresses by tagging them using XML API
    """
    try:
        obj = PaloAltoCustom(config, params)
        obj.setupApiKey(params["username"], params["password"])

        ip_addresses = params.get("ip_addresses", [])
        if not ip_addresses:
            # Support legacy single IP parameter
            ip_addresses = [params.get("ip")]

        tag_name = params.get("tag_name", "malicious")
        persistent = params.get("persistent", 1)
        timeout = params.get("timeout", 0)

        if not ip_addresses:
            raise ConnectorError("No IP addresses provided")

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
                raise ConnectorError(f"Invalid IP address format: {ip_addr}")

            entry = f'<entry ip="{ip_addr}" persistent="{persistent}"><tag><member timeout="{timeout}">{tag_name}</member></tag></entry>'
            entries.append(entry)

        xml_cmd = f"""<uid-message>
  <type>update</type>
  <payload>
    <register>
      {''.join(entries)}
    </register>
  </payload>
</uid-message>"""

        payload = {"type": "user-id", "key": obj._key, "cmd": xml_cmd}

        res_text = obj.make_xml_call(data=payload)
        response_dict = xmltodict.parse(res_text)

        if response_dict.get("response", {}).get("@status") == "success":
            return {
                "status": "success",
                "message": f"Successfully blocked {len(ip_addresses)} IP address(es) with tag '{tag_name}'",
                "blocked_ips": ip_addresses,
                "tag": tag_name,
                "response": response_dict,
            }
        else:
            raise ConnectorError(f"Failed to block IP addresses: {res_text}")

    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def __delete_ip_address(obj, ip):
    xpath = "{0}{1}".format(
        IP_XPATH_GROUP.format(
            vsys_name=obj._virtual_sys, address_group=obj._address_group
        ),
        DEL_ADDR_GRP_XPATH.format(address_name=ip),
    )
    try:
        obj.make_request(action="delete", xpath=xpath)
    except Exception as exp:
        logger.exception("Unblocking of IP failed {0}".format(str(exp)))
        raise ConnectorError("Failed to unblock the IP {0}".format(str(exp)))


def __delete_address_object(obj, ip):
    xpath = IP_ADDRESS_XPATH.format(vsys_name=obj._virtual_sys, address_name=ip)
    try:
        obj.make_request(action="delete", xpath=xpath)
    except Exception as exp:
        logger.debug("Unblocking of IP failed {0}".format(str(exp)))
        if not "cannot be deleted because of references from" in str(exp):
            raise ConnectorError("Failed to unblock the IP {0}".format(str(exp)))


def unblock_ip(config, params):
    """
    Unblock IP addresses by removing tags using XML API
    """
    try:
        obj = PaloAltoCustom(config, params)
        obj.setupApiKey(params["username"], params["password"])

        ip_addresses = params.get("ip_addresses", [])
        if not ip_addresses:
            # Support legacy single IP parameter
            ip_addresses = [params.get("ip")]

        tag_name = params.get("tag_name", "malicious")

        if not ip_addresses:
            raise ConnectorError("No IP addresses provided")

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
                raise ConnectorError(f"Invalid IP address format: {ip_addr}")

            entry = (
                f'<entry ip="{ip_addr}"><tag><member>{tag_name}</member></tag></entry>'
            )
            entries.append(entry)

        xml_cmd = f"""<uid-message>
  <type>update</type>
  <payload>
    <unregister>
      {''.join(entries)}
    </unregister>
  </payload>
</uid-message>"""

        payload = {"type": "user-id", "key": obj._key, "cmd": xml_cmd}

        res_text = obj.make_xml_call(data=payload)
        response_dict = xmltodict.parse(res_text)

        if response_dict.get("response", {}).get("@status") == "success":
            return {
                "status": "success",
                "message": f"Successfully unblocked {len(ip_addresses)} IP address(es) with tag '{tag_name}'",
                "unblocked_ips": ip_addresses,
                "tag": tag_name,
                "response": response_dict,
            }
        else:
            raise ConnectorError(f"Failed to unblock IP addresses: {res_text}")

    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def block_url(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        if len(obj._url_group) == 0 or len(obj._url_policy_name) == 0:
            raise ConnectorError(
                "URL group/URL policy is not configured at configuration to execute this operation"
            )
        xpath = URL_XPATH.format(
            vsys_name=obj._virtual_sys, url_profile_name=obj._url_group
        )
        element = URL_PROF_ELEM.format(url=params.get("url"))

        # Add the URL
        obj.make_request(action="set", xpath=xpath, element=element)
        return check_response(obj)
    except Exception as err:
        logger.debug(" Add the URL to URL Group Failed, error is {0}".format(str(err)))
        raise ConnectorError(
            "Failed to add the URL to URL Group, error is {0}".format(str(err))
        )


def unblock_url(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        if len(obj._url_group) == 0 or len(obj._url_policy_name) == 0:
            raise ConnectorError(
                "Configure URL group/URL policy name to execute this action at connector "
                "configuration page"
            )
        url = params.get("url")
        xpath = "{0}{1}".format(
            URL_XPATH.format(
                vsys_name=obj._virtual_sys, url_profile_name=obj._url_group
            ),
            DEL_URL_XPATH.format(url=url),
        )

        # Remove the Blocked URL from the List
        obj.make_request(action="delete", xpath=xpath)
        return check_response(obj)
    except Exception as err:
        logger.debug(
            "Removing the URL from URL Group Failed, error is {0}".format(str(err))
        )
        raise ConnectorError(
            "Failed to Delete the URL from URL Group, error is {0}".format(str(err))
        )


def block_application(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        if len(obj._app_group) == 0 or len(obj._app_policy_name) == 0:
            raise ConnectorError(
                "Configure Application group/Application policy name to execute this action at connector "
                "configuration page"
            )
        xpath = APPLICATION_XPATH.format(
            vsys_name=obj._virtual_sys, app_group_name=obj._app_group
        )
        element = "<members><member>{app_name}</member></members>".format(
            app_name=params.get("app")
        )

        # Add the App to App group
        obj.make_request(action="set", xpath=xpath, element=element)
        return check_response(obj)
    except Exception as err:
        logger.error(
            "Failed to add the application to application Group, error is {0}".format(
                str(err)
            )
        )
        raise ConnectorError(
            "Failed to add the application to application Group, error is {0}".format(
                str(err)
            )
        )


def unblock_application(config, params):
    try:
        obj = PaloAltoCustom(config)
        obj.setupApiKey(params["username"], params["password"])
        if len(obj._app_group) == 0 or len(obj._app_policy_name) == 0:
            raise ConnectorError(
                "Configure Application group/Application policy name to execute this action at connector "
                "configuration page"
            )
        config_xpath = APPLICATION_XPATH.format(
            vsys_name=obj._virtual_sys, app_group_name=obj._app_group
        )
        xpath = config_xpath + "/members/member[text()='{app_name}']".format(
            app_name=params.get("app")
        )

        # delete the App from the Application Group
        obj.make_request(action="delete", xpath=xpath)
        return check_response(obj)
    except Exception as err:
        logger.debug(
            "Failed to delete the Application from the Application Group: {0}".format(
                str(err)
            )
        )
        raise ConnectorError(
            "Failed to delete the Application from the Application Group: {0}".format(
                str(err)
            )
        )


def get_dynamic_address_groups(config, params):
    """
    Get all Dynamic Address Groups from PaloAlto firewall
    """
    try:
        obj = PaloAltoCustom(config, params)
        obj.setupApiKey(params["username"], params["password"])

        payload = {
            "type": "op",
            "key": obj._key,
            "cmd": "<show><object><dynamic-address-group><all></all></dynamic-address-group></object></show>",
        }

        res_text = obj.make_xml_call(data=payload)
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
        obj = PaloAltoCustom(config, params)
        obj.setupApiKey(params["username"], params["password"])

        payload = {
            "type": "op",
            "key": obj._key,
            "cmd": "<show><object><registered-ip><all></all></registered-ip></object></show>",
        }

        res_text = obj.make_xml_call(data=payload)
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


def xml_check_health(config):
    # try:
    obj = PaloAltoCustom(config)

    res = obj.make_request(
        xpath=HEALTH_CHECK_XPATH.format(vsys_name=obj._virtual_sys), action="get"
    )

    # obj.validate_policies(res, True)
    # return obj.validate_all_groups(True)
    # except Exception as exp:
    #     logger.debug("Check health failed: {0}".format(str(exp)))
    #     raise ConnectorError("Check health failed: {0}".format(str(exp)))


operations = {
    "block_ip": block_ip,
    "unblock_ip": unblock_ip,
    "get_dynamic_address_groups": get_dynamic_address_groups,
    "get_registered_ip": get_registered_ip,
    "block_url": block_url,
    "unblock_url": unblock_url,
    "block_app": block_application,
    "unblock_app": unblock_application,
}
