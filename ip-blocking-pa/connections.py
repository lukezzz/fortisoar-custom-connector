import json
import requests
import xmltodict
from .constants import VSYS_NAME
from connectors.core.connector import ConnectorError, get_logger

logger = get_logger("paloalto-firewall")


def check_response(obj):
    logger.debug("Committing the final changes")
    cmd = "<commit><partial><admin><member>{0}</member></admin></partial></commit>".format(
        obj._username
    )
    data = {"type": "commit", "cmd": cmd, "key": obj._key}
    response = requests.post(obj._server_url + "/api", data, verify=obj._verify_ssl)
    if response.ok:
        response_dict = xmltodict.parse(response.text)
        status = response_dict.get("response").get("@status")
        if status != "success":
            logger.debug(
                "Failed to commit config changes: {0} Status Code: {1}".format(
                    response.text, str(response.status_code)
                )
            )
            raise ConnectorError(
                "Failed to commit config changes: {0} Status Code: {1}".format(
                    response.text, str(response.status_code)
                )
            )
        else:
            return response_dict
    else:
        logger.debug(
            "Failed to commit config changes: {0} Status Code: {1}".format(
                response.text, str(response.status_code)
            )
        )
        raise ConnectorError(
            "Failed to commit config changes: {0} Status Code: {1}".format(
                response.text, str(response.status_code)
            )
        )


class PaloAltoCustom(object):
    def __init__(self, config, params):
        self.log = logger
        self._server_url = params.get("server_url")
        if not self._server_url.startswith(
            "https://"
        ) and not self._server_url.startswith("http://"):
            self._server_url = "https://{0}".format(self._server_url)
        self._username = params.get("username")
        self._password = params.get("password")
        # self._verify_ssl = config.get("verify_ssl") or False
        self._verify_ssl = False
        self._api_type = config.get("api_type")
        self._virtual_sys = (
            config.get("virtual_sys") if config.get("virtual_sys") else VSYS_NAME
        )
        self._key = None
        # self.setupApiKey()
        if self._api_type == "REST APIs":
            self._version = config.get("version")
            if self._version == "v9.0":
                self._version = "9.0"

    def make_rest_call(
        self, endpoint, params=None, headers=None, data=None, method="GET"
    ):
        """
        :param str endpoint: Endpoint to connect
        :param dict params: Query parameters for provided endpoint
        :param dict headers: Authenticate to paloalto server
        :param dict data: Request payload send to paloalto server
        :param str method: HTTP method
        :return: tuple i.e: return two objects (actual response and the cookie)
        """
        url = "{server_address}/restapi/{version}{endpoint}".format(
            server_address=self._server_url, version=self._version, endpoint=endpoint
        )
        logger.info("Requesting URL {0}".format(url))
        try:
            params.update({"location": "vsys", "vsys": self._virtual_sys})
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-PAN-KEY": self._key,
            }
            response = requests.request(
                method,
                url,
                data=data,
                headers=headers,
                verify=self._verify_ssl,
                params=params,
            )
            try:
                from connectors.debug_utils.curl_script import make_curl

                make_curl(
                    method,
                    url,
                    data=data,
                    headers=headers,
                    verify=self._verify_ssl,
                    params=params,
                )
            except:
                pass
            if response.ok:
                if "json" in response.headers.get("Content-Type"):
                    return response.json()
                else:
                    return response.text
            else:
                if "text/html" in response.headers.get("Content-Type"):
                    raise ConnectorError(response.content.decode("utf-8"))
                raise ConnectorError(json.loads(response.content.decode("utf-8")))
        except requests.exceptions.SSLError:
            raise ConnectorError("SSL certificate validation failed")
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError(
                "The request timed out while trying to connect to the server"
            )
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                "The server did not send any data in the allotted amount of time"
            )
        except requests.exceptions.ConnectionError:
            raise ConnectorError("Invalid endpoint or credentials")
        except Exception as err:
            raise ConnectorError(str(err))

    def make_xml_call(self, data):
        try:
            response = requests.post(
                self._server_url + "/api/", params=data, verify=self._verify_ssl
            )
            if response.ok:
                return response.text
            else:
                raise ConnectorError(response.text)
        except Exception as err:
            raise ConnectorError(str(err))

    def setupApiKey(self, username: str, password: str):
        try:
            logger.debug("Fetching the api key.")
            self._key = None
            data = {"type": "keygen", "user": username, "password": password}
            url = "{url}/api/?type=keygen&user={user}&password={pwd}".format(
                url=self._server_url, user=username, pwd=password
            )
            response = requests.post(url, data=data, verify=self._verify_ssl)
            if response.ok:
                xml = response.text
                response_dict = xmltodict.parse(xml)
                status = response_dict.get("response").get("@status")
                if status == "success":
                    self._key = response_dict.get("response").get("result").get("key")
                    logger.debug("api key: {0}".format(self._key))
                else:
                    logger.debug(
                        "Failed to get api key: {0} Status Code: {1}".format(
                            response.text, str(response.status_code)
                        )
                    )
                    raise ConnectorError(
                        "Failed to get api key: {0} Status Code: {1}".format(
                            response.text, str(response.status_code)
                        )
                    )
            else:
                logger.debug("Failed to get api key: {0}".format(response.text))
                raise ConnectorError(
                    "Failed to get api key: {0} Status Code: {1}".format(
                        response.text, str(response.status_code)
                    )
                )
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))

    def make_request(self, action=None, xpath=None, element=None):
        try:
            data = {
                "type": "config",
                "key": self._key,
            }
            if action:
                data["action"] = action
            if xpath:
                data["xpath"] = xpath
            if element:
                data["element"] = element

            logger.info("requesting xml url= {}".format(self._server_url + "/api"))
            response = requests.post(
                self._server_url + "/api", data, verify=self._verify_ssl
            )
            if response.ok:
                response_dict = xmltodict.parse(response.text)
                logger.debug("response is {0}".format(response_dict))
                status = response_dict.get("response").get("@status")
                if status == "success":
                    return response_dict.get("response").get("result", {})
                else:
                    raise ConnectorError(response.text)
            else:
                raise ConnectorError(response.text)
        except Exception as err:
            logger.exception("An exception occurred {0}".format(str(err)))
            raise ConnectorError("An exception occurred {0}".format(str(err)))

    def validate_policies(self, res, xml_flag=False):
        try:
            if xml_flag:
                if res is None:
                    raise ConnectorError("No any policy available on server")
                policy_list = res.get("security", {}).get("rules", {}).get("entry")
            else:
                policy_list = res.get("result", {}).get("entry", [])
            if len(policy_list) > 0:
                ip_flag, url_flag, app_flag = False, False, False

                # Validate all input policies
                for item in policy_list:
                    if item["@name"] == self._ip_policy_name:
                        ip_flag = True
                    if item["@name"] == self._url_policy_name:
                        url_flag = True
                    if item["@name"] == self._app_policy_name:
                        app_flag = True

                if not ip_flag:
                    raise ConnectorError("Invalid IP Policy name given")
                if not url_flag and self._url_policy_name != "":
                    raise ConnectorError("Invalid URL Policy name given")
                if not app_flag and self._app_policy_name != "":
                    raise ConnectorError("Invalid Application Policy name given")
                return True
            else:
                raise ConnectorError("No any policy available on server")
        except Exception as err:
            raise ConnectorError(str(err))

    def validate_all_groups(self, xml_flag=False):
        try:
            if xml_flag:
                # validate ip address group
                ip_xpath = "address-group/entry[@name='{address_group}']".format(
                    address_group=self._address_group
                )
                self._validate_groups_by_xml(ip_xpath, group_type="address group")

                # validate custom URL category
                if len(self._url_group) > 0:
                    url_xpath = "profiles/custom-url-category/entry[@name='{url_profile_name}']".format(
                        url_profile_name=self._url_group
                    )
                    self._validate_groups_by_xml(
                        url_xpath, group_type="custom URL group"
                    )

                # validate application group
                if len(self._app_group) > 0:
                    app_xpath = (
                        "application-group/entry[@name='{app_group_name}']".format(
                            app_group_name=self._app_group
                        )
                    )
                    self._validate_groups_by_xml(
                        app_xpath, group_type="application group object"
                    )
            else:
                # validate ip address group
                self._validate_groups_by_rest(
                    endpoint="/Objects/AddressGroups",
                    group_name=self._address_group,
                    group_type="address group",
                )

                # validate custom URL category
                if len(self._url_group) > 0:
                    self._validate_groups_by_rest(
                        endpoint="/Objects/CustomURLCategories",
                        group_name=self._url_group,
                        group_type="custom URL group",
                    )

                # validate application group
                if len(self._app_group) > 0:
                    self._validate_groups_by_rest(
                        endpoint="/Objects/ApplicationGroups",
                        group_name=self._app_group,
                        group_type="application group object",
                    )
            return True
        except Exception as err:
            raise ConnectorError(str(err))

    def _validate_groups_by_xml(self, input_xpath, group_type):
        try:
            xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name= {1}]/{0}".format(
                input_xpath, self._virtual_sys
            )
            res = self.make_request(action="get", xpath=xpath)
            if not res:
                raise ConnectorError("Input {0} not found".format(group_type))
            count = res.get("@total-count", 0)
            if count != "1":
                raise ConnectorError("Input {0} not found".format(group_type))
        except Exception as err:
            raise ConnectorError(str(err))

    def _validate_groups_by_rest(self, endpoint, group_name, group_type):
        try:
            res = self.make_rest_call(endpoint=endpoint, params={"name": group_name})
            prev_app_list = res.get("result").get("entry")
            if len(prev_app_list) == 1:
                return True
            else:
                raise ConnectionError("Input {0} not found".format(group_type))
        except Exception as err:
            if "Object Not Present" in str(err):
                raise ConnectorError("Input {0} not found".format(group_type))
            raise ConnectorError(str(err))
