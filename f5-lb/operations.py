from ipaddress import ip_address
from connectors.core.connector import get_logger, ConnectorError, api_health_check
from .client.f5_client import F5Client

logger = get_logger("f5-big-ip")


class Endpoint:
    node_list = "/mgmt/tm/ltm/node"
    pool = "/mgmt/tm/ltm/pool"
    vs = "/mgmt/tm/ltm/virtual"
    vs_address = "/mgmt/tm/ltm/virtual-address"


def create_pool(config, params):
    username = params.get("username")
    password = params.get("password")

    client = F5Client(config, username, password)

    partition = params.get("partition")
    monitor = params.get("monitor")
    service_name = params.get("service_name")
    vs_port = params.get("vs_port")

    pool_name = f"pool_{service_name}_{vs_port}"

    # if pool exists, return pool
    check_pool_url = f"{Endpoint.pool}/{pool_name}"
    check_pool_result = client.run(check_pool_url, method="GET")
    if check_pool_result.status_code == 200 and check_pool_result.json():
        return check_pool_result.json()

    pool_members = params.get("pool_members")

    get_node_list_url = (
        f"{Endpoint.node_list}?$filter=partition eq {partition}&$select=name,address"
    )
    node_list = client.run(get_node_list_url, method="GET").json()["items"]

    members_list = []

    for pool_member in pool_members:
        try:
            addr = ip_address(pool_member["address"])
            if (
                addr.is_loopback
                or addr.is_link_local
                or addr.is_multicast
                or addr.is_unspecified
            ):
                logger.exception("Invalid IP Address")
                raise ConnectorError("Invalid IP Address")

        except ValueError:
            logger.exception("Invalid IP Address")
            raise ConnectorError("Invalid IP Address")

        # check if pool_member['address'] is already in node_list, return node
        for node in node_list:
            if node["address"] == pool_member["address"]:
                name = f"""{node["name"]}:{pool_member["port"]}"""
                members_list.append(
                    {
                        "name": name,
                        "address": pool_member["address"],
                    }
                )
                break
        else:
            # create node
            # response = client.run(Endpoint.node_list, method="POST", data={"name": name, "address": pool_member["address"]})
            members_list.append(
                {
                    "name": f"""{pool_member["address"]}:{pool_member["port"]}""",
                    "address": pool_member["address"],
                }
            )

    data = {
        "name": pool_name,
        "members": members_list,
    }

    logger.debug(f"Creating pool with {data}")

    # create pool
    response = client.run(Endpoint.pool, method="POST", data=data)
    if response.status_code == 200:
        return response.json()
    else:
        raise ConnectorError(f"Failed to create pool: {response.text}")


def find_free_vs_add(client, partition, vs_dest_subnet):

    # get current vs address
    url = f"{Endpoint.vs_address}?$filter=partition eq {partition}&$select=name,address,mask"
    vs_address_list = client.run(url, method="GET").json()["items"]

    # find free vs address in vs_dest_subnet range, vs_dest_subnet like 1.1.1.10-1.1.1.20
    vs_dest_subnet = vs_dest_subnet.split("-")
    vs_dest_subnet_start = ip_address(vs_dest_subnet[0])
    vs_dest_subnet_end = ip_address(vs_dest_subnet[1])

    for ip in range(int(vs_dest_subnet_start), int(vs_dest_subnet_end)):
        for vs_address in vs_address_list:
            if ip_address(vs_address["address"]) == ip_address(ip):
                break
        else:
            return str(ip_address(ip))

    # if no free vs address found, raise error
    raise ConnectorError(f"No free vs address left in {vs_dest_subnet} range")


def create_vs(config, params):
    username = params.get("username")
    password = params.get("password")

    vs_dest_subnet = config.get("vs_dest_subnet")

    client = F5Client(config, username, password)

    partition = params.get("partition")

    # vs_name = f"vs_{service_name}_{vs_protocol}{vs_port}"
    vs_name = params.get("vs_name")

    # check vs exists, if exists raise error
    check_vs_url = f"{Endpoint.vs}/{vs_name}"
    check_vs_res = client.run(check_vs_url, method="GET")
    if check_vs_res.status_code == 200 and check_vs_res.json():
        raise ConnectorError(f"VS {vs_name} already exists")

    vs_port = params.get("vs_port")

    new_vs_ip = find_free_vs_add(client, partition, vs_dest_subnet)

    destination = f"{new_vs_ip}:{vs_port}"

    ipProtocol = params.get("ipProtocol")
    httpProfiles = params.get("httpProfiles")
    sslProfiles = params.get("sslProfiles")
    persist = params.get("persist")
    sourceAddressTranslation = params.get("sourceAddressTranslation")
    pool = params.get("pool")

    profiles = []
    if httpProfiles:
        profiles.append(httpProfiles)
    if sslProfiles:
        profiles.append(sslProfiles)

    post_data = {
        "name": vs_name,
        "destination": destination,
        "ipProtocol": ipProtocol,
        "profiles": profiles,
        "persist": persist,
        "sourceAddressTranslation": {
            "type": sourceAddressTranslation,
        },
        "pool": pool,
    }
    logger.debug(post_data)

    # create vs
    response = client.run(Endpoint.vs, method="POST", data=post_data)
    if response.status_code == 200:
        return response.json()
    else:
        raise ConnectorError(f"Failed to create vs: {response.text}")


def get_config(config):
    server_url = config.get("server_url")
    verify_ssl = config.get("verify_ssl")
    if all([server_url]):
        if not server_url.startswith("https://"):
            server_url = "https://" + server_url
        return server_url, verify_ssl
    else:
        logger.exception("Configuration field is required")
        raise ConnectorError("Configuration field is required")


def _check_health(config):
    hostname, verify_ssl = get_config(config)
    logger.info("F5-BIG-IP Test Connectivity")
    endpoint = "{0}/tmui/login.jsp".format(str(hostname))
    try:
        response = api_health_check(endpoint, method="GET", verify=verify_ssl)
        if response:
            logger.info("F5-BIG-IP Connector Available")
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
            logger.exception("Hostname {0} is not known".format(hostname))
            raise ConnectorError("Hostname {0} is not known".format(hostname))
        else:
            logger.exception("Exception occurred : {0}".format(err))
            raise ConnectorError("failure: {}".format(str(err)))


operations = {
    "create_pool": create_pool,
    "create_vs": create_vs,
}
