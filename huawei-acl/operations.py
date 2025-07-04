from .huawei_os_connect import HuaweiOSConnect
import validators
from connectors.core.connector import get_logger, ConnectorError
import ipaddress
import re
from typing import List

logger = get_logger("huawei-os")


def verify_ipv4_or_subnet(input_str):
    try:
        network = ipaddress.ip_network(input_str, strict=False)
        return str(network.network_address)
    except ValueError:
        return False


def get_vpn_instance_list(output):
    logger.info("get_vpn_instance_list(): output =  '{}'".format(output))
    # match VPN instance names
    # vpn_instance_list = re.findall(r"^\s+(\S+)\s+IPv4", output, re.MULTILINE)
    vpn_instance_list = re.findall(r"^\s+(\S+)\s+IPv4\s*$", output, re.MULTILINE)
    return vpn_instance_list


def test_and_match(command, cmd_output):
    # match Vlanif\d+ and route must be "Direct" type
    vlan_id_pattern = re.compile(
        r"\s+Direct\s+\d+\s+\d+\s+\S+\s+\d+\.\d+\.\d+\.\d+\s+Vlanif(\d+)"
    )
    match = vlan_id_pattern.search(cmd_output)
    if match and match.group(1):
        vlan_id = match.group(1)
        curr_data = {
            "Command": command,
            "Output": cmd_output,
            "Status": "Success",
            "VlanID": vlan_id,
        }
        logger.info("Command executed Successfully")
        return curr_data
    return False


class HuaweiOS(HuaweiOSConnect):
    def __init__(self):
        super(HuaweiOS, self).__init__()

    def ping_ip_address(self, ip):
        """
        Pinging IP Address from device to get mac address
        """
        logger.info(
            "ping_ip_address(): pinging IP {} from device to get MAC Address".format(ip)
        )
        cmd_to_run = "ping {ip} ".format(ip=ip)
        cmd_output = self.execute_command(cmd_to_run)
        data = self.reformat_cmd_output(cmd_output)
        if data is None:
            logger.info(
                "ping_ip_address(): send_command = {0},ip = {1}".format(
                    cmd_to_run, str(ip)
                )
            )
            raise ConnectorError("Ping IP address failed for IP {}".format(ip))
        return True

    def get_route_info(self, params):
        """
        Function that executes the show ip route command with test ip/subnet
        """
        self.make_connection(params)
        # verify the ip address
        ip_addr = params.get("ip_addr")
        test_ip = verify_ipv4_or_subnet(ip_addr)
        if not test_ip:
            logger.info("Invalid IP address")
            raise ConnectorError("Invalid IP address")

        check_vrf_cmd = "display ip vpn-instance"
        check_vrf_output = self.execute_command(check_vrf_cmd)

        vrf_list = get_vpn_instance_list(check_vrf_output)
        logger.info("get_route_info(): VPN instance list =  '{}'".format(vrf_list))

        if not vrf_list:
            command = f"display ip routing-table {test_ip}"
            logger.info("get_route_info(): Executed command =  '{}'".format(command))
            cmd_output = self.execute_command(command)
            cmd_output = self.reformat_cmd_output(
                cmd_output, rem_command=True, to_list=False
            )

            result = test_and_match(command, cmd_output)
            if result:
                return result

        for vrf in vrf_list:

            command = f"display ip routing-table vpn-instance {vrf} {test_ip}"
            logger.info("get_route_info(): Executed command =  '{}'".format(command))
            cmd_output = self.execute_command(command)
            cmd_output = self.reformat_cmd_output(
                cmd_output, rem_command=True, to_list=False
            )
            result = test_and_match(command, cmd_output)
            if result:
                return result

        # if no match found recheck the default routing table
        command = f"display ip routing-table {test_ip}"
        logger.info("get_route_info(): Executed command =  '{}'".format(command))
        cmd_output = self.execute_command(command)
        cmd_output = self.reformat_cmd_output(
            cmd_output, rem_command=True, to_list=False
        )
        result = test_and_match(command, cmd_output)
        if result:
            return result

        curr_data = {"Command": "", "Output": "", "Status": "Failed"}
        logger.info("Command executed Failed")
        self.disconnect()
        return curr_data

    def send_config_set(self, params):
        """
        Function that sends the configuration to the device
        """
        if self.make_connection(params) is not True:
            raise ConnectorError("Connection Failed")

        cmd_to_run = "sys"
        cmd_output = self.execute_command(cmd_to_run)
        logger.info("Executed command = {}".format(cmd_to_run))

        for command in params.get("commands"):
            cmd_output = self.execute_command(command)
            logger.info("Executed command =  '{}'".format(command))

        data = self.reformat_cmd_output(cmd_output, rem_command=True, to_list=False)

        if "Duplicate" in data:
            raise ConnectorError("Duplicate sequence number")

        commit_cmd = "commit"
        cmd_output = self.execute_command(commit_cmd)
        self.disconnect()
        return data

    def save_config(self, params):
        """
        Function that saves the configuration to the device
        """

        if self.make_connection(params) is not True:
            raise ConnectorError("Connection Failed")

        cmd_list = ["save", "commit"]
        for cmd in cmd_list:
            try:
                cmd_output = self.execute_command(cmd)
                logger.info("Executed command =  '{}'".format(cmd))
            except:
                return "Failed to save configuration"
        data = self.reformat_cmd_output(cmd_output, rem_command=True, to_list=False)
        self.disconnect()
        return data


def _check_health(config):
    return True


def get_config(config, params):
    obj = HuaweiOS()
    return obj.get_config_info(config)


def get_version(config, params):
    obj = HuaweiOS()
    return obj.get_version_info(config)


def get_route_info(config, params):
    obj = HuaweiOS()
    return obj.get_route_info(params)


def config_acl(config, params):
    obj = HuaweiOS()
    return obj.send_config_set(params)


def save_config(config, params):
    obj = HuaweiOS()
    return obj.save_config(params)


operations = {
    "get_config": get_config,
    "get_version": get_version,
    "get_route_info": get_route_info,
    "config_acl": config_acl,
    "save_config": save_config,
}
