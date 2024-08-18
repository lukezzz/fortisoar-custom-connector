from .cisco_os_connect import CiscoOSConnect
import validators
from connectors.core.connector import get_logger, ConnectorError
import ipaddress
import re
from typing import List

logger = get_logger("cisco-os")


def verify_ipv4_or_subnet(input_str):
    try:
        network = ipaddress.ip_network(input_str, strict=False)
        return str(network.network_address)
    except ValueError:
        return False


class CiscoOS(CiscoOSConnect):
    def __init__(self):
        super(CiscoOS, self).__init__()

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

    def retrieve_mac_address_for_ip(self, ip, ping_ip):
        """
        Getting mac address of specified IP
        """
        mac_addr = None
        logger.info("Getting mac address of specified ip")
        cmd_to_run = "show ip device tracking ip {ip}".format(ip=ip)
        cmd_output = self.execute_command(cmd_to_run)
        data = self.reformat_cmd_output(cmd_output, rem_command=True, to_list=False)
        if data is None:
            logger.info("retrieve_mac_address_for_ip failed")
            raise ConnectorError("Getting mac address of specified IP failed")
        else:
            cmd_output = self.reformat_cmd_output(
                cmd_output, rem_command=True, to_list=False
            )
            if not cmd_output:
                if ping_ip:
                    self.ping_ip_address(ip)
                    return self.retrieve_mac_address_for_ip(ip, False)
                logger.info(
                    "Unable to get the mac of the ip. Please specify the mac address"
                )
                raise ConnectorError(
                    "Unable to get the mac of the ip. Please specify the mac address"
                )
            cmd_output = cmd_output.strip()
            if not cmd_output:
                if ping_ip:
                    self.ping_ip_address(ip)
                    return self.retrieve_mac_address_for_ip(ip, False)
                logger.info(
                    "Unable to get the mac of the ip. Please specify the mac address"
                )
                raise ConnectorError(
                    "Unable to get the mac of the ip. Please specify the mac address"
                )
            ip_entry = cmd_output.split()
            if not ip_entry:
                if ping_ip:
                    self.ping_ip_address(ip)
                    return self.retrieve_mac_address_for_ip(ip, False)
                logger.info(
                    "Unable to get the mac of the ip. Please specify the mac address"
                )
                raise ConnectorError(
                    "Unable to get the mac of the ip. Please specify the mac address"
                )
            mac_addr = ip_entry[-1].strip()
            if not mac_addr:
                if ping_ip:
                    self.ping_ip_address(ip)
                    return self.retrieve_mac_address_for_ip(ip, False)
                logger.info(
                    "Unable to get the mac of the ip. Please specify the mac address"
                )
                raise ConnectorError(
                    "Unable to get the mac of the ip. Please specify the mac address"
                )
        return mac_addr

    def set_vlan_of_mac(self, mac, params):
        """
        Set VLAN id on an interface
        """
        mac = mac.lower()
        s = mac.replace(":", "").replace(".", "")
        mac_addr = ".".join((s[:4], s[4:8], s[8:12]))
        logger.info("Searching for mac on device")
        cmd_to_run = "show mac address-table address {mac_addr}".format(
            mac_addr=mac_addr
        )
        cmd_output = self.execute_command(cmd_to_run)
        cmd_output = self.reformat_cmd_output(
            cmd_output, rem_command=True, to_list=False
        )
        cmd_output = cmd_output.strip()
        if not cmd_output:
            logger.info("MAC address not found on device")
            raise ConnectorError("MAC address not found on device")

        curr_vlan_id, mac_addr, type1, port = tuple(cmd_output.split())
        vlan_id = params.get("vlan_id")
        if int(curr_vlan_id) == int(vlan_id):
            logger.info("VLAN ID is same as required")
            return True
        cmd_to_run = "show interfaces status ".format(port=port)
        cmd_output = self.execute_command(cmd_to_run)
        cmd_output = self.reformat_cmd_output(
            cmd_output, rem_command=True, to_list=False
        )
        if not cmd_output:
            logger.info(
                "Port {} information could not be found on the device".format(port)
            )
        parts = cmd_output.split()
        port_vlan = parts[-4]
        if port_vlan == "trunk":
            override_trunk = params.get("override_trunk")
            modify = bool(override_trunk)
            if not modify:
                logger.info(
                    "Vlan of trunk port {} not modified,"
                    " re-run action with Set vlan of trunk port".format(port)
                )
        cmd_to_run = "configure terminal"
        cmd_output = self.execute_command(cmd_to_run)
        logger.info("Executed command = {}".format(cmd_to_run))
        cmd_to_run = "interface {port}".format(port=port)
        cmd_output = self.execute_command(cmd_to_run)
        logger.info("Executed command = {}".format(cmd_to_run))
        cmd_to_run = "switchport access vlan {vlan_id}".format(vlan_id=vlan_id)
        cmd_output = self.execute_command(cmd_to_run)
        data = self.reformat_cmd_output(cmd_output, rem_command=True, to_list=False)
        if data is None:
            logger.info("set_vlan_of_mac():" + "Command execution failed")
            raise ConnectorError("Command execution failed")
        if self.get_cmd_output_status(cmd_output) is False:
            if cmd_output:
                logger.info("set_vlan_of_mac():" + "Message from device")
            data = self.reformat_cmd_output(
                cmd_output, rem_command=False, to_list=False
            )

        return data

    def set_vlan_id_of_port(self, config, params):
        """
        This action takes as input either a MAC address or an IP. If an IP is specified,
        it will try to get the MAC address for that IP. It executes command to get to the MAC address.
        If this call fails to get any data, that means the device currently does not have any information about the IP.
        It then proceeds to ping the IP from the device (action parameters permitting).
        Once the MAC address is known, the port that the MAC address is connected to is queried by running the
        'show mac address-table address {mac_addr} | include {mac_addr} ' command. This command gives back a switchport.
        Once the switchport is known, the vlan of the switchport is modified to the required value.
        If the switchport happens to be a trunk port, then the vlan is only changed if the action parameters permit it.
        """
        if self.make_connection(config) is not True:
            logger.info("Connection Failed")
            raise ConnectorError("Connection Failed")
        else:

            endpoint = params.get("ip_macaddress")
            ping_ip = params.get("ping_ip")
            mac = endpoint
            if validators.ipv4(str(endpoint)):
                mac = self.retrieve_mac_address_for_ip(endpoint, ping_ip)
                if mac is None:
                    logger.info("In set_vlan_id_of_port: Mac is None")
                    raise ConnectorError("Mac is None")
            logger.info("CiscoCatalyst Json MAC Address = {}".format(mac))
            return self.set_vlan_of_mac(mac, params)

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

        command = f"show ip route {test_ip} vrf all"
        cmd_output = self.execute_command(command)
        cmd_output = self.reformat_cmd_output(
            cmd_output, rem_command=True, to_list=False
        )

        vlan_id_pattern = re.compile(r"Vlan(\d+)|direct")
        match = vlan_id_pattern.search(cmd_output)
        if match:
            vlan_id = match.group(1)
            curr_data = {
                "Command": command,
                "Output": cmd_output,
                "Status": "Success",
                "VlanID": vlan_id,
            }
            logger.info("get_route_info(): Executed command =  '{}'".format(command))
            logger.info("Command executed Successfully")
            return curr_data

        curr_data = {"Command": command, "Output": cmd_output, "Status": "Success"}
        logger.info("get_route_info(): Executed command =  '{}'".format(command))
        logger.info("Command executed Successfully")
        self.disconnect()
        return curr_data

    def send_config_set(self, params):
        """
        Function that sends the configuration to the device
        """
        if self.make_connection(params) is not True:
            raise ConnectorError("Connection Failed")

        cmd_to_run = "configure terminal"
        cmd_output = self.execute_command(cmd_to_run)
        logger.info("Executed command = {}".format(cmd_to_run))

        commands = "\n".join(params.get("commands"))
        cmd_output = self.execute_command(commands)
        logger.info("Executed command =  '{}'".format(commands))

        data = self.reformat_cmd_output(cmd_output, rem_command=True, to_list=False)

        if data and "Duplicate" in data:
            raise ConnectorError("Duplicate sequence number")
        self.disconnect()
        return data

    def save_config(self, params):
        """
        Function that saves the configuration to the device
        """

        if self.make_connection(params) is not True:
            raise ConnectorError("Connection Failed")

        cmd_to_run = "copy running-config startup-config"
        cmd_output = self.execute_command(cmd_to_run)
        data = self.reformat_cmd_output(cmd_output, rem_command=True, to_list=False)
        self.disconnect()
        return data


def _check_health(config):
    # obj = CiscoOS()
    # try:
    #     logger.info("Connected Successfully")
    #     return obj.test_connectivity(config)
    # except:
    #     logger.exception("Invalid URL or Credentials")
    #     raise ConnectorError("Invalid URL or Credentials")
    return True


def get_config(config, params):
    obj = CiscoOS()
    return obj.get_config_info(config)


def get_version(config, params):
    obj = CiscoOS()
    return obj.get_version_info(config)


def configure_vlan(config, params):
    obj = CiscoOS()
    return obj.set_vlan_id_of_port(config, params)


def get_route_info(config, params):
    obj = CiscoOS()
    return obj.get_route_info(params)


def config_acl(config, params):
    obj = CiscoOS()
    return obj.send_config_set(params)


def save_config(config, params):
    obj = CiscoOS()
    return obj.save_config(params)


operations = {
    "get_config": get_config,
    "get_version": get_version,
    "get_route_info": get_route_info,
    "config_acl": config_acl,
    "save_config": save_config,
}
