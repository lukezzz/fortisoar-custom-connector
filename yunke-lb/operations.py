from ipaddress import ip_address
from connectors.core.connector import get_logger, ConnectorError, api_health_check
from .client.yunke_client import YunkeClient

logger = get_logger("yunke-lb")


class Endpoint:
    slb_node_list = "/adc/v3.0/slb/node"
    slb_pool = "/adc/v3.0/slb/pool"
    slb_vs = "/adc/v3.0/slb/vserver"
    # slb_vs_address = "/adc/v3.0/slb/virtual-address" # we need to get slb_vs_address from slb_vs


def find_free_vs_ip(client, vs_dest_subnet):
    """Find a free virtual server IP address in the given subnet range"""

    # Get current vserver list to extract used IP addresses
    response = client.run(Endpoint.slb_vs, method="GET")
    if response.status_code != 200:
        raise ConnectorError(f"Failed to get vserver list: {response.text}")

    data = response.json()
    if (
        data.get("res", {}).get("status") != "success"
        and data.get("res", {}).get("status") != "failure"
    ):
        raise ConnectorError(
            f"API returned error: {data.get('res', {}).get('msg', 'Unknown error')}"
        )

    vserver_list = data.get("data", {}).get("slb_vserver", [])

    # Extract used IP addresses from vserver VIPs (format: "IP:PORT")
    used_ips = set()
    for vserver in vserver_list:
        vip = vserver.get("vip", "")
        if ":" in vip:
            ip_part = vip.split(":")[0]
            try:
                used_ips.add(ip_address(ip_part))
            except ValueError:
                logger.warning(f"Invalid IP format in VIP: {vip}")

    # Parse the destination subnet range, format like "1.1.1.10-1.1.1.20"
    if "-" not in vs_dest_subnet:
        raise ConnectorError("vs_dest_subnet must be in format 'start_ip-end_ip'")

    vs_dest_subnet_parts = vs_dest_subnet.split("-")
    if len(vs_dest_subnet_parts) != 2:
        raise ConnectorError("vs_dest_subnet must be in format 'start_ip-end_ip'")

    try:
        vs_dest_subnet_start = ip_address(vs_dest_subnet_parts[0].strip())
        vs_dest_subnet_end = ip_address(vs_dest_subnet_parts[1].strip())
    except ValueError as e:
        raise ConnectorError(f"Invalid IP address in subnet range: {e}")

    # Find free IP address in the range
    current_ip = vs_dest_subnet_start
    while current_ip <= vs_dest_subnet_end:
        if current_ip not in used_ips:
            return str(current_ip)
        current_ip += 1

    # If no free IP address found, raise error
    raise ConnectorError(f"No free IP address left in {vs_dest_subnet} range")


def get_new_vs_ip(config, params):
    """Get a new free virtual server IP address from the configured subnet range"""
    host = params.get("host")
    username = params.get("username")
    password = params.get("password")

    # Get the destination subnet from config or params
    vs_dest_subnet = config.get("vs_dest_subnet") or params.get("vs_dest_subnet")

    if not vs_dest_subnet:
        raise ConnectorError(
            "vs_dest_subnet must be configured in connector config or provided as parameter"
        )

    client = YunkeClient(config, host, username, password)

    try:
        new_vs_ip = find_free_vs_ip(client, vs_dest_subnet)
        # return {
        #     "new_ip": new_vs_ip,
        #     "subnet_range": vs_dest_subnet,
        #     "status": "success",
        # }
        return new_vs_ip

    except ConnectorError:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error finding free IP: {e}")
        raise ConnectorError(f"Failed to get new vs ip: {str(e)}")


def get_slb_pool_list(config, params):
    """Get list of SLB pools"""
    host = params.get("host")
    username = params.get("username")
    password = params.get("password")

    client = YunkeClient(config, host, username, password)

    response = client.run(Endpoint.slb_pool, method="GET")
    if response.status_code == 200:
        data = response.json()
        # Return specific pool data instead of full response
        if ():
            return data.get("data", {}).get("slb_pool", [])
        else:
            raise ConnectorError(
                f"API returned error: {data.get('res', {}).get('msg', 'Unknown error')}"
            )
    else:
        raise ConnectorError(f"Failed to get pool list: {response.text}")


def get_slb_pool_detail(config, params):
    """Get detailed information about a specific SLB pool"""
    host = params.get("host")
    username = params.get("username")
    password = params.get("password")
    pool_name = params.get("pool_name")

    client = YunkeClient(config, host, username, password)

    response = client.run(f"{Endpoint.slb_pool}?name={pool_name}", method="GET")
    if response.status_code == 200:
        data = response.json()
        # Return specific pool detail instead of full response
        if data.get("res", {}).get("status") == "success":
            pools = data.get("data", {}).get("slb_pool", [])
            if pools:
                return pools[0]  # Return the first (and should be only) pool
            else:
                raise ConnectorError(f"Pool {pool_name} not found")
        else:
            raise ConnectorError(
                f"API returned error: {data.get('res', {}).get('msg', 'Unknown error')}"
            )
    else:
        raise ConnectorError(f"Failed to get pool detail: {response.text}")


def get_healthcheck_list(config, params):
    """Get list of available health checks"""
    host = params.get("host")
    username = params.get("username")
    password = params.get("password")

    client = YunkeClient(config, host, username, password)

    response = client.run("/adc/v3.0/slb/healthcheck", method="GET")
    if response.status_code == 200:
        data = response.json()
        # Return specific healthcheck data instead of full response
        if data.get("res", {}).get("status") == "success":
            return data.get("data", {}).get("healthcheck", [])
        else:
            raise ConnectorError(
                f"API returned error: {data.get('res', {}).get('msg', 'Unknown error')}"
            )
    else:
        raise ConnectorError(f"Failed to get healthcheck list: {response.text}")


def create_slb_node(config, params):
    """Create a new SLB node"""
    host = params.get("host")
    username = params.get("username")
    password = params.get("password")

    client = YunkeClient(config, host, username, password)

    node_name = params.get("name")
    node_ip = params.get("ip")
    node_type = params.get("node_type", "ip")
    maxconn = params.get("maxconn", "0")
    maxcps = params.get("maxcps", "0")
    healthcheck_relation = params.get("healthcheck_relation", "all")
    enable = params.get("enable", "on")

    # Validate IP address
    try:
        addr = ip_address(node_ip)
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

    payload = {
        "name": node_name,
        "node_type": node_type,
        "ip": node_ip,
        "maxconn": str(maxconn),
        "maxcps": str(maxcps),
        "healthcheck_relation": healthcheck_relation,
        "enable": enable,
    }

    response = client.run(Endpoint.slb_node_list, method="POST", data=payload)
    if response.status_code == 200:
        data = response.json()
        # Return specific node creation result
        if data.get("res", {}).get("status") == "success":
            return {
                "message": f"Node {node_name} created successfully",
                "node_name": node_name,
                "node_ip": node_ip,
                "status": "success",
            }
        else:
            raise ConnectorError(
                f"API returned error: {data.get('res', {}).get('msg', 'Unknown error')}"
            )
    else:
        raise ConnectorError(f"Failed to create node: {response.text}")


def create_slb_pool(config, params):
    """Create a new SLB pool with members"""
    host = params.get("host")
    username = params.get("username")
    password = params.get("password")

    client = YunkeClient(config, host, username, password)

    pool_name = params.get("pool_name")
    method = params.get("method", "rr")  # round-robin as default
    healthcheck_uuids = params.get("healthcheck_uuids", [])
    healthcheck_relation = params.get("healthcheck_relation", "all")
    pool_desc = params.get("pool_desc", "")
    silent_period = params.get("silent_period", "10")
    pool_members = params.get("pool_members", [])

    # Check if pool already exists
    check_pool_url = f"{Endpoint.slb_pool}?name={pool_name}"
    check_pool_result = client.run(check_pool_url, method="GET")
    if check_pool_result.status_code == 200:
        pool_data = check_pool_result.json()
        if pool_data.get("data", {}).get("slb_pool"):
            logger.info(f"Pool {pool_name} already exists")
            return {
                "message": f"Pool {pool_name} already exists",
                "pool_name": pool_name,
                "status": "exists",
            }

    # Prepare healthcheck list
    healthcheck_list = []
    for hc_uuid in healthcheck_uuids:
        healthcheck_list.append({"healthcheck_uuid": hc_uuid})

    # Prepare pool data
    pool_data = {
        "name": pool_name,
        "method": method or "rr",
        "healthcheck": healthcheck_list,
        "healthcheck_relation": healthcheck_relation or "all",
        "pool_desc": pool_desc or "",
        "silent_period": str(silent_period) or "10",
        "elastic_enable": "off",
        "snmp_monitor_enable": "off",
        "pg_enable": "off",
        "pg_activations": "",
        "warmup_enable": "off",
        "warmup_period": "10",
        "warmup_increase": "100",
        "action_on_service_down": "null",
    }

    # Optional elastic configuration
    if params.get("elastic_enable") == "on":
        pool_data.update(
            {
                "elastic_enable": "on",
                "elastic_minactive": params.get("elastic_minactive", "1"),
                "elastic_time": params.get("elastic_time", "180"),
                "elastic_type": params.get("elastic_type", "flow"),
                "elastic_limit": params.get("elastic_limit", "50-100"),
            }
        )

    # Optional warmup configuration
    if params.get("warmup_enable") == "on":
        pool_data.update(
            {
                "warmup_enable": "on",
                "warmup_period": params.get("warmup_period", "10"),
                "warmup_increase": params.get("warmup_increase", "100"),
            }
        )

    logger.debug(f"Creating pool with data: {pool_data}")

    # Create pool
    response = client.run(Endpoint.slb_pool, method="POST", data=pool_data)
    pool_uuid = None
    if response.status_code == 200:
        data = response.json()
        if data.get("res", {}).get("status") == "success":
            logger.debug(f"Pool creation response: {data}")
            # Get the pool UUID from creation response
            pool_uuid = data.get("data", {}).get("uuid")
            if pool_uuid:
                logger.debug(f"Pool created with UUID: {pool_uuid}")
            else:
                raise ConnectorError(f"Pool creation succeeded but no UUID returned")
        else:
            # Check if the error is because pool already exists
            error_msg = data.get("res", {}).get("msg", "")
            if data.get("res", {}).get("status") == "failure" and (
                "exsited" in error_msg or "existed" in error_msg
            ):
                logger.info(
                    f"Pool {pool_name} already exists, getting UUID from detail API"
                )
                # Get pool UUID from detail API
                pool_detail_response = client.run(
                    f"{Endpoint.slb_pool}/{pool_name}", method="GET"
                )
                if pool_detail_response.status_code == 200:
                    pool_detail_data = pool_detail_response.json()
                    if pool_detail_data.get("data", {}).get("slb_pool"):
                        pool_uuid = pool_detail_data["data"]["slb_pool"]["uuid"]
                        logger.debug(f"Found existing pool UUID: {pool_uuid}")
                    else:
                        raise ConnectorError(
                            f"Pool {pool_name} not found in detail API"
                        )
                else:
                    raise ConnectorError(
                        f"Failed to get pool details: {pool_detail_response.text}"
                    )
            else:
                raise ConnectorError(
                    f"API returned error: {data.get('res', {}).get('msg', 'Unknown error')}"
                )
    else:
        raise ConnectorError(f"Failed to create pool: {response.text}")

    # Process pool members if provided
    created_members = []
    if pool_members and pool_uuid:
        for i, member in enumerate(pool_members):
            member_address = member.get("address")
            member_port = member.get("port")

            if not member_address or not member_port:
                logger.warning(f"Skipping invalid member {i}: missing address or port")
                continue

            # Generate node name based on pool name and member address
            node_name = f"{member_address}-{member_port}"

            # Validate IP address
            try:
                addr = ip_address(member_address)
                if (
                    addr.is_loopback
                    or addr.is_link_local
                    or addr.is_multicast
                    or addr.is_unspecified
                ):
                    logger.warning(f"Invalid IP Address: {member_address}")
                    continue
            except ValueError:
                logger.warning(f"Invalid IP Address: {member_address}")
                continue

            # Create node
            node_data = {
                "name": node_name,
                "node_type": "ip",
                "ip": member_address,
                "maxconn": str(params.get("maxconn", "0")),
                "maxcps": "0",
                "healthcheck_relation": healthcheck_relation,
                "enable": params.get("enable", "on"),
            }

            logger.debug(f"Creating node: {node_data}")

            # Create the node
            node_response = client.run(
                Endpoint.slb_node_list, method="POST", data=node_data
            )
            node_uuid = None

            if node_response.status_code == 200:
                node_result = node_response.json()
                if node_result.get("res", {}).get("status") == "success":
                    logger.debug(f"Node creation response: {node_result}")
                    # Get the node UUID from creation response
                    node_uuid = node_result.get("data", {}).get("uuid")
                    if node_uuid:
                        logger.debug(f"Node created with UUID: {node_uuid}")
                    else:
                        raise ConnectorError(
                            f"Node creation succeeded but no UUID returned"
                        )
                else:
                    # Check if the error is because node already exists
                    error_msg = node_result.get("res", {}).get("msg", "")
                    if node_result.get("res", {}).get("status") == "failure" and (
                        "exsited" in error_msg or "existed" in error_msg
                    ):
                        logger.info(
                            f"Node {node_name} already exists, getting UUID from detail API"
                        )
                        # Get node UUID from detail API
                        node_detail_response = client.run(
                            f"{Endpoint.slb_node_list}/{node_name}", method="GET"
                        )
                        if node_detail_response.status_code == 200:
                            node_detail_data = node_detail_response.json()
                            if node_detail_data.get("data", {}).get("slb_node"):
                                node_uuid = node_detail_data["data"]["slb_node"]["uuid"]
                                logger.debug(f"Found existing node UUID: {node_uuid}")
                            else:
                                logger.warning(
                                    f"Node {node_name} not found in detail API"
                                )
                        else:
                            logger.warning(
                                f"Failed to get node details: {node_detail_response.text}"
                            )
                    else:
                        logger.warning(f"Node creation response: {node_result}")
            else:
                logger.warning(
                    f"Node creation failed, might already exist: {node_response.text}"
                )

            # If node creation failed, try to get existing node UUID
            if not node_uuid:
                node_detail_response = client.run(
                    f"{Endpoint.slb_node_list}?name={node_name}", method="GET"
                )
                if node_detail_response.status_code == 200:
                    node_detail_data = node_detail_response.json()
                    if node_detail_data.get("data", {}).get("slb_node"):
                        node_uuid = node_detail_data["data"]["slb_node"][0]["uuid"]
                        logger.debug(f"Found existing node UUID: {node_uuid}")
                    else:
                        logger.error(f"Node {node_name} not found after creation")
                        continue
                else:
                    logger.error(
                        f"Failed to get node details: {node_detail_response.text}"
                    )
                    continue

            # Add member to pool
            new_member_payload = {
                "weight": str(params.get("weight", "10")),
                "maxconn": str(params.get("maxconn", "0")),
                "maxreq": str(params.get("maxreq", "0")),
                "bandwidth": str(params.get("bandwidth", "0")),
                "slb_node_uuid": node_uuid,
                "healthcheck": healthcheck_list,
                "healthcheck_relation": healthcheck_relation,
                "elastic_enable": params.get("elastic_enable", "off"),
                "elastic_virtualmachine": params.get("elastic_virtualmachine", ""),
                "enable": params.get("enable", "on"),
                "conn_pool_size": str(params.get("conn_pool_size", "1024")),
                "pg_priority": str(params.get("pg_priority", "0")),
                "address": f"{node_uuid}:{member_port}",
            }

            logger.debug(
                f"Adding member to pool {pool_name} with payload: {new_member_payload}"
            )

            # Add member to pool
            add_member_endpoint = f"{Endpoint.slb_pool}/{pool_uuid}/rserver"
            member_response = client.run(
                add_member_endpoint, method="POST", data=new_member_payload
            )

            if member_response.status_code == 200:
                member_data = member_response.json()
                if member_data.get("res", {}).get("status") == "success":
                    created_members.append(
                        {
                            "address": member_address,
                            "port": member_port,
                            "node_name": node_name,
                            "node_uuid": node_uuid,
                        }
                    )
                    logger.info(
                        f"Member {member_address}:{member_port} added to pool {pool_name} successfully"
                    )
                else:
                    logger.error(
                        f"Failed to add member {member_address}:{member_port}: {member_data.get('res', {}).get('msg', 'Unknown error')}"
                    )
            else:
                logger.error(
                    f"Failed to add member {member_address}:{member_port} to pool: {member_response.text}"
                )

    return {
        "message": f"Pool {pool_name} created successfully with {len(created_members)} members",
        "pool_name": pool_name,
        "method": method,
        "created_members": created_members,
        "status": "success",
        "pool_uuid": pool_uuid,
    }


def get_vserver_list(config, params):
    """Get list of virtual servers"""
    host = params.get("host")
    username = params.get("username")
    password = params.get("password")

    client = YunkeClient(config, host, username, password)

    response = client.run(Endpoint.slb_vs, method="GET")
    if response.status_code == 200:
        data = response.json()
        # Return specific vserver data instead of full response
        if data.get("res", {}).get("status") == "success":
            return data.get("data", {}).get("slb_vserver", [])
        else:
            raise ConnectorError(
                f"API returned error: {data.get('res', {}).get('msg', 'Unknown error')}"
            )
    else:
        raise ConnectorError(f"Failed to get vserver list: {response.text}")


def create_vserver(config, params):
    """Create a new virtual server"""
    host = params.get("host")
    username = params.get("username")
    password = params.get("password")

    client = YunkeClient(config, host, username, password)

    vs_name = params.get("vs_name")
    vip = params.get("vip")  # format: "172.16.60.181:20444"
    ip_type = params.get("ip_type", "ipv4")
    protocol = params.get("protocol", "smart-http")
    ssloffload = params.get("ssloffload", False)  # Default to off
    mode = params.get("mode", "nat")
    enable = params.get("enable", "on")
    slb_pool_uuid = params.get("slb_pool_uuid")
    vs_desc = params.get("vs_desc", "")

    # Check if vserver already exists
    check_vs_url = f"{Endpoint.slb_vs}?name={vs_name}"
    check_vs_result = client.run(check_vs_url, method="GET")
    if check_vs_result.status_code == 200:
        vs_data = check_vs_result.json()
        if vs_data.get("data", {}).get("slb_vserver"):
            raise ConnectorError(f"Virtual server {vs_name} already exists")

    # mapping protocol
    protocol = "smart-http" if protocol.lower() == "http" else protocol.lower()

    # Prepare vserver data
    vserver_data = {
        "name": vs_name,
        "vip": vip,
        "ip_type": ip_type,
        "protocol": protocol,
        "mode": mode,
        "enable": enable,
        "slb_pool_uuid": slb_pool_uuid,
        "vs_desc": vs_desc,
        "vlan_traffic_type": "0",
        "vlans": [],
    }

    # Optional SSL profile
    ssl_profile_uuid = params.get("ssl_profile_uuid")
    if ssloffload and ssl_profile_uuid:
        vserver_data["ssl_profile_uuid"] = ssl_profile_uuid

    # Optional web security profile
    web_security_profile_uuid = params.get("web_security_profile_uuid")
    if web_security_profile_uuid:
        vserver_data["web_security_profile_uuid"] = web_security_profile_uuid

    # Optional persistence profile
    persistence_profile_uuid = params.get("persistence_profile_uuid")
    if persistence_profile_uuid:
        vserver_data["persistence_profile_uuid"] = persistence_profile_uuid

    # Optional HTTP profile
    http_profile_uuid = params.get("http_profile_uuid")
    if http_profile_uuid:
        vserver_data["http_profile_uuid"] = http_profile_uuid

    # Optional TCP/UDP profile
    tcp_udp_profile_uuid = params.get("tcp_udp_profile_uuid")
    if tcp_udp_profile_uuid:
        vserver_data["tcp_udp_profile_uuid"] = tcp_udp_profile_uuid

    # Optional NAT configuration
    nat_name = params.get("nat_name", ["default"])
    vserver_data["nat_name"] = nat_name

    # Optional backup pool
    slb_backup_pool_uuid = params.get("slb_backup_pool_uuid")
    if slb_backup_pool_uuid:
        vserver_data["slb_backup_pool_uuid"] = slb_backup_pool_uuid

    logger.debug(f"Creating vserver with data: {vserver_data}")

    # Create vserver
    response = client.run(Endpoint.slb_vs, method="POST", data=vserver_data)
    if response.status_code == 200:
        data = response.json()
        logger.debug(f"Vserver creation response: {data}")
        # Return specific vserver creation result
        if data.get("res", {}).get("status") == "success":
            return {
                "message": f"Virtual server {vs_name} created successfully",
                "vs_name": vs_name,
                "vip": vip,
                "protocol": protocol,
                "status": "success",
            }
        else:
            raise ConnectorError(
                f"API returned error: {data.get('res', {}).get('msg', 'Unknown error')}"
            )
    else:
        raise ConnectorError(f"Failed to create vserver: {response.text}")


def _check_health(config):
    pass


def add_pool_member(config, params):
    """Add a server to an existing pool by creating a node first, then adding it to the pool"""
    host = params.get("host")
    username = params.get("username")
    password = params.get("password")
    pool_name = params.get("pool_name")
    server_address = params.get("server_address")  # format: "172.16.60.126:6181"
    node_name = params.get("node_name")
    weight = params.get("weight", "10")
    maxconn = params.get("maxconn", "0")
    maxreq = params.get("maxreq", "0")
    enable = params.get("enable", "on")
    bandwidth = params.get("bandwidth", "0")
    conn_pool_size = params.get("conn_pool_size", "1024")
    pg_priority = params.get("pg_priority", "0")
    elastic_enable = params.get("elastic_enable", "off")
    elastic_virtualmachine = params.get("elastic_virtualmachine", "")
    healthcheck_uuids = params.get("healthcheck_uuids", [])
    healthcheck_relation = params.get("healthcheck_relation", "all")

    client = YunkeClient(config, host, username, password)

    # Extract IP and port from server_address
    if ":" in server_address:
        server_ip, server_port = server_address.split(":", 1)
    else:
        raise ConnectorError("server_address must be in format 'IP:PORT'")

    # Step 1: Create the node first if it doesn't exist
    node_data = {
        "name": node_name,
        "node_type": "ip",
        "ip": server_ip,
        "maxconn": str(maxconn),
        "maxcps": "0",  # Default value
        "healthcheck_relation": healthcheck_relation,
        "enable": enable,
    }

    logger.debug(f"Creating node: {node_data}")

    # Create the node
    node_response = client.run(Endpoint.slb_node_list, method="POST", data=node_data)
    node_uuid = None

    if node_response.status_code == 200:
        node_result = node_response.json()
        if node_result.get("res", {}).get("status") == "success":
            logger.info(f"Node {node_name} created successfully")
            # Get the node UUID from creation response
            node_uuid = node_result.get("data", {}).get("uuid")
            if node_uuid:
                logger.debug(f"Node created with UUID: {node_uuid}")
            else:
                raise ConnectorError(f"Node creation succeeded but no UUID returned")
        else:
            logger.warning(f"Node creation response: {node_result}")
    else:
        logger.warning(
            f"Node creation failed, might already exist: {node_response.text}"
        )

    # Step 2: If node creation failed, get existing node UUID
    if not node_uuid:
        node_detail_response = client.run(
            f"{Endpoint.slb_node_list}?name={node_name}", method="GET"
        )
        if node_detail_response.status_code == 200:
            node_detail_data = node_detail_response.json()
            if node_detail_data.get("data", {}).get("slb_node"):
                node_uuid = node_detail_data["data"]["slb_node"][0]["uuid"]
                logger.debug(f"Found existing node UUID: {node_uuid}")
            else:
                raise ConnectorError(f"Node {node_name} not found after creation")
        else:
            raise ConnectorError(
                f"Failed to get node details: {node_detail_response.text}"
            )

    # Step 3: Get the pool details to get pool UUID
    pool_detail_response = client.run(
        f"{Endpoint.slb_pool}?name={pool_name}", method="GET"
    )
    if pool_detail_response.status_code != 200:
        raise ConnectorError(f"Failed to get pool details: {pool_detail_response.text}")

    pool_data = pool_detail_response.json()
    if not pool_data.get("data", {}).get("slb_pool"):
        raise ConnectorError(f"Pool {pool_name} not found")

    current_pool = pool_data["data"]["slb_pool"][0]
    pool_uuid = current_pool["uuid"]

    # Step 4: Check if member already exists in pool
    existing_members = current_pool.get("slb_rserver", [])
    for existing_member in existing_members:
        if existing_member.get("address") == server_address:
            logger.info(f"Member {server_address} already exists in pool {pool_name}")
            return {
                "message": f"Member {server_address} already exists in pool {pool_name}",
                "pool_name": pool_name,
                "member_address": server_address,
                "status": "exists",
            }

    # Step 5: Prepare healthcheck list
    healthcheck_list = []
    for hc_uuid in healthcheck_uuids:
        healthcheck_list.append({"healthcheck_uuid": hc_uuid})

    # Step 6: Create new pool member data structure based on API reference
    # Format: /adc/v3.0/slb/pool/{pool_uuid}/rserver
    new_member_payload = {
        "weight": str(weight),
        "maxconn": str(maxconn),
        "maxreq": str(maxreq),
        "bandwidth": str(bandwidth),
        "slb_node_uuid": node_uuid,
        "healthcheck": healthcheck_list,
        "healthcheck_relation": healthcheck_relation,
        "elastic_enable": elastic_enable,
        "elastic_virtualmachine": elastic_virtualmachine,
        "enable": enable,
        "conn_pool_size": str(conn_pool_size),
        "pg_priority": str(pg_priority),
        "address": f"{node_uuid}:{server_port}",  # Format: node_uuid:port
    }

    logger.debug(
        f"Adding member to pool {pool_name} with payload: {new_member_payload}"
    )

    # Step 7: Add member to pool using the specific endpoint
    add_member_endpoint = f"{Endpoint.slb_pool}/{pool_uuid}/rserver"
    response = client.run(add_member_endpoint, method="POST", data=new_member_payload)

    if response.status_code == 200:
        data = response.json()
        if data.get("res", {}).get("status") == "success":
            return {
                "message": f"Member {server_address} added to pool {pool_name} successfully",
                "pool_name": pool_name,
                "member_address": server_address,
                "node_name": node_name,
                "node_uuid": node_uuid,
                "status": "success",
            }
        else:
            raise ConnectorError(
                f"API returned error: {data.get('res', {}).get('msg', 'Unknown error')}"
            )
    else:
        raise ConnectorError(f"Failed to add member to pool: {response.text}")


def get_node_list(config, params):
    """Get list of all SLB nodes"""
    host = params.get("host")
    username = params.get("username")
    password = params.get("password")

    client = YunkeClient(config, host, username, password)

    response = client.run(Endpoint.slb_node_list, method="GET")
    if response.status_code == 200:
        data = response.json()
        # Return specific node data instead of full response
        if data.get("res", {}).get("status") == "success":
            return data.get("data", {}).get("slb_node", [])
        else:
            raise ConnectorError(
                f"API returned error: {data.get('res', {}).get('msg', 'Unknown error')}"
            )
    else:
        raise ConnectorError(f"Failed to get node list: {response.text}")


def get_node_detail(config, params):
    """Get detailed information about a specific SLB node"""
    host = params.get("host")
    username = params.get("username")
    password = params.get("password")
    node_name = params.get("node_name")

    client = YunkeClient(config, host, username, password)

    response = client.run(f"{Endpoint.slb_node_list}?name={node_name}", method="GET")
    if response.status_code == 200:
        data = response.json()
        # Return specific node detail instead of full response
        if data.get("res", {}).get("status") == "success":
            nodes = data.get("data", {}).get("slb_node", [])
            if nodes:
                return nodes[0]  # Return the first (and should be only) node
            else:
                raise ConnectorError(f"Node {node_name} not found")
        else:
            raise ConnectorError(
                f"API returned error: {data.get('res', {}).get('msg', 'Unknown error')}"
            )
    else:
        raise ConnectorError(f"Failed to get node detail: {response.text}")


def get_master_ip(config, params):
    """Get the master IP address and UUID by checking HA status"""
    host = params.get("host")
    username = params.get("username")
    password = params.get("password")

    client = YunkeClient(config, host, username, password)

    # Get HA status
    response = client.run("/adc/v3.0/ha/vrrp/", method="GET")
    if response.status_code != 200:
        raise ConnectorError(f"Failed to get HA status: {response.text}")

    data = response.json()
    if data.get("res", {}).get("status") != "success":
        raise ConnectorError(
            f"API returned error: {data.get('res', {}).get('msg', 'Unknown error')}"
        )

    ha_list = data.get("data", {}).get("ha", [])
    if not ha_list:
        raise ConnectorError("No HA configuration found")

    # Check all HA configurations to find the master
    master_ip = None
    master_uuid = None
    current_state = None
    peer_ip = None

    for ha_config in ha_list:
        config_state = ha_config.get("current_state", "").lower()
        config_peer_ip = ha_config.get("peer_ip", "")
        config_uuid = ha_config.get("uuid", "")

        if config_state == "master":
            # Current node is master, return current host IP
            master_ip = host
            master_uuid = config_uuid
            current_state = config_state
            peer_ip = config_peer_ip
            break
        elif config_state in ["backup", "slave"]:
            # Current node is not master, peer IP should be master
            master_ip = config_peer_ip if config_peer_ip else host
            master_uuid = config_uuid
            current_state = config_state
            peer_ip = config_peer_ip

    # If no master found, use the first configuration as fallback(Standalone mode)
    if master_ip is None:
        current_state = "standalone"
        peer_ip = ""
        master_uuid = ""
        master_ip = host

    return {
        "master_ip": master_ip,
        "master_uuid": master_uuid,
        "current_state": current_state,
        "peer_ip": peer_ip,
        "status": "success",
    }


def sync_config(config, params):
    """Synchronize configuration in HA cluster"""
    host = params.get("host")
    username = params.get("username")
    password = params.get("password")
    master_uuid = params.get("master_uuid", "")

    client = YunkeClient(config, host, username, password)

    # Prepare sync payload
    sync_payload = {"config_sync": "all"}

    logger.debug(
        f"Syncing config for HA UUID {master_uuid} with payload: {sync_payload}"
    )

    # Execute config sync
    sync_endpoint = f"/adc/v3.0/ha/vrrp/{master_uuid}"
    response = client.run(sync_endpoint, method="PUT", data=sync_payload)

    if response.status_code == 200:
        data = response.json()
        if data.get("res", {}).get("status") == "success":
            return {
                "message": f"Config sync completed successfully for HA UUID {master_uuid}",
                "master_uuid": master_uuid,
                "config_sync": "all",
                "status": "success",
            }
        else:
            raise ConnectorError(
                f"API returned error: {data.get('res', {}).get('msg', 'Unknown error')}"
            )
    else:
        raise ConnectorError(f"Failed to sync config: {response.text}")


operations = {
    "get_slb_pool_list": get_slb_pool_list,
    "get_slb_pool_detail": get_slb_pool_detail,
    "create_slb_pool": create_slb_pool,
    "create_slb_node": create_slb_node,
    "get_node_list": get_node_list,
    "get_node_detail": get_node_detail,
    "get_healthcheck_list": get_healthcheck_list,
    "get_vserver_list": get_vserver_list,
    "create_vserver": create_vserver,
    "add_pool_member": add_pool_member,
    "get_new_vs_ip": get_new_vs_ip,
    "get_master_ip": get_master_ip,
    "sync_config": sync_config,
}
