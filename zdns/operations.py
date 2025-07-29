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
        raise ConnectorError(result.content)


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


def dns_proximity_config(config, params):
    """
    Process DNS proximity config data and create gmembers, gpool, and dzone
    Expected params format:
    {
        "username": "user",
        "password": "pass",
        "dzone_name": "fqb-gm.fuguo",
        "gmembers": [
            {"dc_name": "GDS_DC", "ip": "10.10.12.220", "port": 80},
            {"dc_name": "ZR_DC", "ip": "10.210.12.201", "port": 80}
        ]
    }
    """
    logger.info(params)
    c = ZDNSClient(config)
    username = params["username"]
    password = params["password"]
    dzone_name = params["dzone_name"]
    gmembers = params["gmembers"]

    # Create gmembers
    gmember_list = []
    gmember_responses = []

    for gmember in gmembers:
        try:
            dc_name = gmember["dc_name"]
            ip = gmember["ip"]
            port = gmember["port"]
            gmember_name = f"{dc_name}_{ip}"

            # Create gmember
            gmember_response = c.create_gmember(
                username, password, dc_name, gmember_name, ip, port
            )

            gmember_responses.append(
                {
                    "gmember_name": gmember_name,
                    "response": (
                        gmember_response.json()
                        if gmember_response.status_code == 200
                        else gmember_response.text
                    ),
                    "status_code": gmember_response.status_code,
                }
            )

            gmember_list.append(
                {
                    "dc_name": dc_name,
                    "gmember_name": gmember_name,
                    "ratio": 1,
                    "enable": "yes",
                }
            )

        except Exception as e:
            gmember_responses.append(
                {"error": f"Error processing gmember {gmember}: {str(e)}"}
            )
            continue

    # Generate gpool name
    if "fullgoal.com.cn" in dzone_name:
        domain_name = "fullgoal.com.cn."
    else:
        domain_name = "fuguo."

    domain_name_list = dzone_name.split(".")
    domain_name_list = list(filter(None, domain_name_list))
    gpool_name = "_".join(domain_name_list) + "_pool"

    # Create gpool
    gpool_response = c.create_gpool(username, password, gpool_name, gmember_list)

    # Create dzone
    dzone_response = c.create_dzone(username, password, dzone_name, gpool_name)

    result = {
        "dzone_name": dzone_name,
        "gpool_name": gpool_name,
        "gmember_responses": gmember_responses,
        "gpool_response": {
            "response": (
                gpool_response.json()
                if gpool_response.status_code == 200
                else gpool_response.text
            ),
            "status_code": gpool_response.status_code,
        },
        "dzone_response": {
            "response": (
                dzone_response.json()
                if dzone_response.status_code == 200
                else dzone_response.text
            ),
            "status_code": dzone_response.status_code,
        },
    }

    log_info = "%s DNS proximity config processed for domain: %s" % (
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        dzone_name,
    )
    logger.info(log_info)

    return result


def _check_health(config):
    try:
        c = ZDNSClient(config)
        # c.get_zone_list("a", "b", "c")
    except Exception as e:
        logger.exception("{}".format(e))
        raise ConnectorError("{}".format(e))


operations = {
    "find_domain": find_domain,
    "add_domain": add_domain,
    "dns_proximity_config": dns_proximity_config,
}
