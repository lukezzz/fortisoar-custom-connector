import paramiko, socket, sys
from connectors.core.connector import get_logger, ConnectorError
from .constants import *

logger = get_logger("cisco-os")


class CiscoOSConnect:
    def __init__(self):
        self._ssh_client = None
        self._shell_channel = None
        return

    def wait_till_timeout(self, size):
        """
        Waits till we have some data
        """
        self._shell_channel.settimeout(RECEIVE_FIRST_DATA_TIMEOUT)
        output = ""
        while True:
            try:
                data = self._shell_channel.recv(size)
                data = data.decode("utf-8")
                output += data
                self._shell_channel.settimeout(RECEIVE_SECOND_DATA_TIMEOUT)
            except socket.timeout:
                break
            except:
                return False, None, sys.exc_info()[0]
        return True, output, None

    def make_connection(self, params):
        if self._shell_channel is not None:
            return True
        else:
            status_code = self.connect_to_shell(params)
            if not status_code:
                return status_code
            cmd_list = ["enable", params.get("password"), "terminal pager 0"]
            for cmd in cmd_list:
                try:
                    cmd_output = self.execute_command(cmd)
                    logger.info("Executed Command {}".format(cmd))
                except Exception as error:
                    logger.info("Exception Occured {0}".format(error))
                    logger.info("Exception Occured in command {0}".format(cmd))
                    raise ConnectorError(str(error))
            return True

    def test_connectivity(self, params):
        """
        Validate the asset configuration for connectivity.
        This action runs a few commands on the device to check the connection and credentials.
        """
        if not self.make_connection(params):
            logger.info("Connection Failed")
            raise ConnectorError("Invalid URL or Credentials")
        logger.info("Connected Successfully")
        return True

    def connect_to_shell(self, params):
        """
        Starts the shell
        """

        logger.debug(params)
        server = params.get("hostname")
        user = params.get("username")
        password = params.get("password")
        self._ssh_client = paramiko.SSHClient()
        self._ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        logger.info(
            " connect_to_shell(): Prog connecting to " + "server {}".format(server)
        )
        try:
            self._ssh_client.connect(
                hostname=server,
                username=user,
                password=password,
                allow_agent=False,
                look_for_keys=False,
            )
        except Exception as error:
            logger.info("connect_to_shell():{}".format(error))
            raise ConnectorError("Could not establish ssh connection to device")

        try:
            self._shell_channel = self._ssh_client.invoke_shell()
        except Exception as error:
            logger.info("connect_to_shell():{}".format(error))
            self._ssh_client.close()
            raise ConnectorError("Could not establish ssh connection to device")

        ret_code, output, exc = self.wait_till_timeout(MAX_SIZE_FOR_OUTPUT)
        if not ret_code:
            raise ConnectorError("Read from device failed")
        return True

    def execute_command(self, command):
        """
        Send a command to the server on the provided channel
        """
        size = MAX_SIZE_FOR_OUTPUT
        self._shell_channel.settimeout(RECEIVE_SECOND_DATA_TIMEOUT)
        try:
            self._shell_channel.send(command + "\n")
        except Exception as error:
            logger.exception(
                "On device execution of command '{0}' failed, with error {1}".format(
                    command, error
                )
            )
            raise ConnectorError(
                "On device execution of command '{}' failed".format(command)
            )
        ret_code, output, exc = self.wait_till_timeout(size)
        if not ret_code:
            logger.exception("Read from device failed")
            raise ConnectorError("Read from device failed")
        return output

    def reformat_cmd_output(self, cmd_output, rem_command=True, to_list=True):
        """
        Reformat the command output
        """
        if cmd_output is None:
            return
        else:
            try:
                data_lines = cmd_output.splitlines()
                data_lines.pop()
                if rem_command:
                    del data_lines[0]
                if to_list:
                    return data_lines
            except:
                return

            return "\r\n".join(data_lines)

    def get_cmd_output_status(self, cmd_output):
        """
        Get the status of command output
        """
        if not cmd_output:
            return True
        if cmd_output.find("ERROR:") != -1:
            return False
        if cmd_output.find("Invalid input detected at ") != -1:
            return False
        return True

    def get_version_info(self, params):
        """
        Function that executes the show version command
        """
        self.make_connection(params)
        command = "show version"
        cmd_output = self.execute_command(command)
        cmd_output = self.reformat_cmd_output(
            cmd_output, rem_command=True, to_list=False
        )
        os_version = "nxos" if "NX-OS" in cmd_output else "ios"
        curr_data = {
            "Command": command,
            "Output": cmd_output,
            "Status": "Success",
            "OS": os_version,
        }
        logger.info("get_version_info(): Executed command =  '{}'".format(command))
        logger.info("Command executed Successfully")
        return curr_data

    def get_config_info(self, params):
        """
        Function that executes the show run command
        """
        if self.make_connection(params) is not True:
            raise ConnectorError("Connection Failed")

        command = "show run"
        cmd_output = self.execute_command(command)
        cmd_output = self.reformat_cmd_output(
            cmd_output, rem_command=True, to_list=False
        )
        curr_data = {}
        curr_data[0] = {"Command": command, "Output": cmd_output, "Status": "Success"}
        logger.info("Executed command =  '{}'".format(command))

        command = "show vlan"
        cmd_output = self.execute_command(command)
        cmd_output = self.reformat_cmd_output(
            cmd_output, rem_command=True, to_list=False
        )
        curr_data[1] = {"Command": command, "Output": cmd_output, "Status": "Success"}
        logger.info("Executed command =  '{}' ".format(command))
        return curr_data
