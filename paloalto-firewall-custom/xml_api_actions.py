""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from .constants import *
from .connections import *
from connectors.core.connector import ConnectorError, get_logger

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
    obj = PaloAltoCustom(config)
    obj.setupApiKey(params["username"], params["password"])
    logger.debug(
        "Adding IP address {0} to Address for blocking".format(params.get("ip"))
    )
    # Add the IP address to Address

    __add_ip_address(obj, params.get("ip"))

    logger.debug("Adding Address to Address group")
    # Add address to address group
    __add_address_to_group(obj, params.get("ip").replace("/", "-"))
    return check_response(obj)


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
    ip = params.get("ip")
    # Delete the IP address from the Address group
    obj = PaloAltoCustom(config)
    obj.setupApiKey(params["username"], params["password"])
    __delete_ip_address(obj, ip.replace("/", "-"))
    __delete_address_object(obj, ip.replace("/", "-"))
    return check_response(obj)


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
    "block_url": block_url,
    "unblock_url": unblock_url,
    "block_app": block_application,
    "unblock_app": unblock_application,
}
