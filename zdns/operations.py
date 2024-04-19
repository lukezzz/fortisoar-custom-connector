"""
This file will be auto-generated on each "new operation action", so avoid editing in this file.
"""

import datetime
import re
import base64

from connectors.core.connector import get_logger, ConnectorError

from .client.zdns_client import ZDNSClient

logger = get_logger("zdns")


def add_domain(config, params):
    logger.info(params)
    c = ZDNSClient(config)
    username = params["username"]
    password = params["password"]
    view_name = params.get("view_name", "default")
    domain_name = params["domain_name"]
    domain_ip = params["domain_ip"]
    # domain_add = domain_name.split(zone_name)[0][0:-1]
    domain_add, zone_name = domain_name.split(".", 1)
    result = c.add_rrs(
        username, password, view_name, zone_name, domain_add, "A", [domain_ip]
    )
    if result.status_code == 200:
        log_info = "%s %s %s ADD sucess~\n" % (
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            domain_name,
            domain_ip,
        )
        logger.info(log_info)
        return result.json()
    else:
        log_info = "%s %s %s ADD failed!!!\n" % (
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            domain_name,
            domain_ip,
        )
        logger.info(log_info)
        raise ConnectorError("EXISTS")


# def __find_zone(domain_name, zone_list):
#     name_split = domain_name.split('.')
#     for i, v in enumerate(name_split):
#         zone_name = '.'.join(name_split[i:])
#         if zone_name in zone_list:
#             return zone_name


# def find_zone(config, params):
#     username = params["username"]
#     password = params["password"]
#     view_name = params["view_name"]
#     domain_name = params["domain_name"]
#
#     c = ZDNSClient(config)
#     zone_list = c.get_zone_list(username, password, view_name)
#     return __find_zone(domain_name, zone_list)


def find_domain(config, params):
    username = params["username"]
    password = params["password"]
    domain_name = params["domain_name"]
    c = ZDNSClient(config)
    return c.find_domain(username, password, domain_name)


def _check_health(config):
    try:
        c = ZDNSClient(config)
        # c.get_zone_list("a", "b", "c")
    except Exception as e:
        logger.exception("{}".format(e))
        raise ConnectorError("{}".format(e))


operations = {"find_domain": find_domain, "add_domain": add_domain}
