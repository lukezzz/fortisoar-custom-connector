import ipaddress
import json
from connectors.core.connector import get_logger, ConnectorError
from .constants import *

logger = get_logger("hillstone-fw")


def addr2dec(addr):
    """将点分十进制IP地址转换成十进制整数"""
    # Handle CIDR notation by stripping the subnet mask
    if "/" in addr:
        addr = addr.split("/")[0]
    items = [int(x) for x in addr.split(".")]
    return sum([items[i] << [24, 16, 8, 0][i] for i in range(4)])


def dec2addr(dec):
    """将十进制整数IP转换成点分十进制的字符串IP地址"""
    return ".".join([str(dec >> x & 0xFF) for x in [24, 16, 8, 0]])


def _get_list_from_str_or_list(params, param_name, is_ip=False):
    """Convert string or list parameter to list"""
    value = params.get(param_name, [])
    if isinstance(value, str):
        if value.strip():
            result = [x.strip() for x in value.split(",")]
        else:
            result = []
    elif isinstance(value, list):
        result = value
    else:
        result = []

    if is_ip:
        # Validate IP addresses
        validated_ips = []
        for ip in result:
            try:
                ipaddress.ip_address(ip)
                validated_ips.append(ip)
            except ValueError:
                logger.warning(f"Invalid IP address: {ip}")
                continue
        return validated_ips

    return result


def _validate_vsys(config, params):
    """Validate VSYS configuration"""
    vsys_id = params.get("vsys_id") or config.get("vsys_id")
    if not vsys_id:
        vsys_id = "1"  # Default VSYS
    return vsys_id


def generate_address_name(ip_addr):
    """Generate address name based on IP"""
    try:
        ip_obj = ipaddress.ip_network(ip_addr, strict=False)
        if ip_obj.prefixlen == 32:  # Single host
            return f"Host_{ip_obj.network_address}"
        else:  # Network
            return f"Network_{ip_obj.network_address}_{ip_obj.prefixlen}"
    except ValueError:
        return f"IP_{ip_addr.replace('.', '_')}"


def generate_group_name(base_name):
    """Generate group name"""
    return f"BlockGroup_{base_name}"


if __name__ == "__main__":
    print(addr2dec("123.1.1.1"))
