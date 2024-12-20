from ipaddress import ip_address
from connectors.core.connector import get_logger, ConnectorError, api_health_check
from .client.f5_client import F5Client

logger = get_logger("f5-big-ip")


class Endpoint:
    node_list = "/mgmt/tm/ltm/node"
    pool = "/mgmt/tm/ltm/pool"
    vs = "/mgmt/tm/ltm/virtual"
    vs_address = "/mgmt/tm/ltm/virtual-address"
    gtm_server = "/mgmt/tm/gtm/server"
    gtm_pool = "/mgmt/tm/gtm/pool"
    gtm_wide_ip = "/mgmt/tm/gtm/wideip"


def check_ha(config, params):
    host = params.get("host")
    username = params.get("username")
    password = params.get("password")

    client = F5Client(config, host, username, password)

    response = client.run("/mgmt/tm/cm/failover-status?$select=status", method="GET")
    if response.status_code == 200:
        status = response.json()["entries"][
            "https://localhost/mgmt/tm/cm/failover-status/0"
        ]["nestedStats"]["entries"]["status"]["description"]
        if status == "ACTIVE":
            return True
        else:
            return False
    else:
        raise ConnectorError(f"Failed to check HA: {response.text}")


def sync_config(config, params):
    host = params.get("host")
    username = params.get("username")
    password = params.get("password")
    group_name = config.get("group_name")

    client = F5Client(config, host, username, password)

    payload = {"command": "run", "utilCmdArgs": f"config-sync to-group {group_name}"}

    response = client.run("/mgmt/tm/cm", method="POST", data=payload)
    if response.status_code == 200:
        return response.json()
    else:
        raise ConnectorError(f"Failed to sync config: {response.text}")


def create_pool(config, params):
    host = params.get("host")
    username = params.get("username")
    password = params.get("password")

    client = F5Client(config, host, username, password)

    partition = params.get("partition")
    monitor = params.get("monitor")
    pool_name = params.get("pool_name")

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

    data = {"name": pool_name, "members": members_list, "monitor": monitor}

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


def get_new_vs_ip(config, params):
    username = params.get("username")
    password = params.get("password")
    host = params.get("host")

    vs_dest_subnet = config.get("vs_dest_subnet")

    client = F5Client(config, host, username, password)

    partition = params.get("partition")

    new_vs_ip = find_free_vs_add(client, partition, vs_dest_subnet)

    if new_vs_ip:
        return new_vs_ip
    else:
        raise ConnectorError(f"Failed to get vs ip")


def create_vs(config, params):
    username = params.get("username")
    password = params.get("password")
    host = params.get("host")

    vs_dest_subnet = config.get("vs_dest_subnet")

    client = F5Client(config, host, username, password)

    partition = params.get("partition")

    # vs_name = f"vs_{service_name}_{vs_protocol}{vs_port}"
    vs_name = params.get("vs_name")

    # check vs exists, if exists raise error
    check_vs_url = f"{Endpoint.vs}/{vs_name}"
    check_vs_res = client.run(check_vs_url, method="GET")
    if check_vs_res.status_code == 200 and check_vs_res.json():
        raise ConnectorError(f"VS {vs_name} already exists")

    vs_port = params.get("vs_port")

    new_vs_ip = params.get("vs_ip")
    if not new_vs_ip:
        new_vs_ip = find_free_vs_add(client, partition, vs_dest_subnet)

    destination = f"{new_vs_ip}:{vs_port}"

    ipProtocol = params.get("ipProtocol")
    httpProfiles = params.get("httpProfiles")
    sslProfiles = params.get("sslProfiles")
    persist = params.get("persist")
    sourceAddressTranslation = params.get("sourceAddressTranslation")
    pool = params.get("pool")
    ssloffload = params.get("ssloffload")

    if ipProtocol:
        ipProtocol = ipProtocol.lower()
        # ignore the sslProfiles if ipProtocol is not http
        if ipProtocol in ["tcp", "udp"]:
            httpProfiles = None
            sslProfiles = None

    profiles = []
    if ipProtocol == "http" and httpProfiles:
        ipProtocol = "tcp"
        profiles.append(httpProfiles)
    if bool(ssloffload) and sslProfiles:
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


def create_gtm_server(config, params):
    username = params.get("username")
    password = params.get("password")
    host = None

    client = F5Client(config, host, username, password)

    service_name = params.get("service_name")

    name = service_name
    # check if gtm server exists, return gtm server
    check_gtm_server_url = f"{Endpoint.gtm_server}/{name}"
    check_gtm_server_result = client.run(check_gtm_server_url, method="GET")
    if check_gtm_server_result.status_code == 200 and check_gtm_server_result.json():
        return check_gtm_server_result.json()

    # create gtm server
    partition = params.get("partition")
    datacenter = params.get("datacenter")
    monitor = params.get("monitor")
    product = params.get("product")
    virtual_servers = params.get("virtual_servers")
    gtm_servers = params.get("gtm_servers")
    for server in gtm_servers:
        # verify name should be IP address
        try:
            ip_address(server["name"])
        except ValueError:
            raise ConnectorError("Invalid IP Address")

    post_data = {
        "name": name,
        "partition": partition,
        "datacenter": datacenter,
        "monitor": monitor,
        "product": product,
        "virtualServers": virtual_servers,
        "addresses": gtm_servers,
    }
    logger.debug(post_data)

    response = client.run(Endpoint.gtm_server, method="POST", data=post_data)
    if response.status_code == 200:
        return response.json()
    else:
        raise ConnectorError(f"Failed to create gtm server: {response.text}")


def create_gtm_pool(config, params):
    username = params.get("username")
    password = params.get("password")
    host = None

    client = F5Client(config, host, username, password)

    service_name = params.get("service_name")
    record_type = "a"
    name = service_name
    # check if gtm pool exists, return gtm pool
    check_gtm_pool_url = f"{Endpoint.gtm_pool}/{record_type}/{name}"
    check_gtm_pool_result = client.run(check_gtm_pool_url, method="GET")
    if check_gtm_pool_result.status_code == 200 and check_gtm_pool_result.json():
        return check_gtm_pool_result.json()

    # create gtm pool
    loadBalancingMode = params.get("loadBalancingMode")
    members = params.get("members")

    post_data = {
        "name": name,
        "loadBalancingMode": loadBalancingMode,
        "members": members,
    }
    logger.debug(post_data)
    create_url = f"{Endpoint.gtm_pool}/{record_type}"
    response = client.run(create_url, method="POST", data=post_data)
    if response.status_code == 200:
        return response.json()
    else:
        raise ConnectorError(f"Failed to create gtm pool: {response.text}")


def create_gtm_wide_ip(config, params):
    username = params.get("username")
    password = params.get("password")
    host = None

    client = F5Client(config, host, username, password)

    service_name = params.get("service_name")

    name = service_name

    record_type = params.get("record_type", "a")
    # check if gtm wide ip exists, return gtm wide ip
    check_gtm_wide_ip_url = f"{Endpoint.gtm_wide_ip}/{record_type}/{name}"
    check_gtm_wide_ip_result = client.run(check_gtm_wide_ip_url, method="GET")
    if check_gtm_wide_ip_result.status_code == 200 and check_gtm_wide_ip_result.json():
        return check_gtm_wide_ip_result.json()

    # create gtm wide ip
    pools = params.get("pools")

    post_data = {
        "name": name,
        "pools": pools,
    }
    logger.debug(post_data)
    create_url = f"{Endpoint.gtm_wide_ip}/{record_type}"
    response = client.run(create_url, method="POST", data=post_data)
    if response.status_code == 200:
        return response.json()
    else:
        raise ConnectorError(f"Failed to create gtm wide ip: {response.text}")


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
    pass


operations = {
    "create_pool": create_pool,
    "create_vs": create_vs,
    "get_new_vs_ip": get_new_vs_ip,
    "create_gtm_server": create_gtm_server,
    "create_gtm_pool": create_gtm_pool,
    "create_gtm_wide_ip": create_gtm_wide_ip,
    "check_ha": check_ha,
    "sync_config": sync_config,
}
