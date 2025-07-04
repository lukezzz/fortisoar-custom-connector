from connectors.core.connector import get_logger, ConnectorError
from requests.adapters import HTTPAdapter, Retry
import requests
import base64

try:
    import urllib.parse as urlencoding
except:
    import urllib as urlencoding

logger = get_logger("hillstone-fw")


class TimeoutHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self.timeout = 30
        if "timeout" in kwargs:
            self.timeout = kwargs["timeout"]
            del kwargs["timeout"]
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        timeout = kwargs.get("timeout")
        if timeout is None:
            kwargs["timeout"] = self.timeout
        return super().send(request, **kwargs)


class HillStoneFWClient:
    def __init__(self, config, username, password):

        self.host = config.get("url")
        self.vsys_id = config.get("vsys_id")

        self.username = base64.b64encode(username.encode()).decode()
        self.password = base64.b64encode(password.encode()).decode()
        self._logged = False

        self._session = requests.Session()
        self._session.verify = config.get("verify_ssl")
        retries = Retry(
            total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504]
        )
        self._session.mount("http://", TimeoutHTTPAdapter(max_retries=retries))
        self._session.mount("https://", TimeoutHTTPAdapter(max_retries=retries))

        self.url_prefix = f"https://{self.host}/rest"

    def login(self, is_api_login=False):
        logger.debug("Logging in to Hillstone")
        url = (
            f"{self.url_prefix}/api/login"
            if is_api_login
            else f"{self.url_prefix}/login"
        )
        login_data = {
            "username": self.username,
            "password": self.password,
            "lang": "en",
        }
        res = self._session.post(url, json=login_data, verify=False)
        logger.debug("Login request body: %s", login_data)
        logger.debug("Login response: %s", res.text)
        res_json = res.json()
        if res_json["success"]:
            res_data = (
                res_json["result"][0]
                if isinstance(res_json["result"], list)
                else res_json["result"]
            )
            if res_data["passwordExpired"] == 1:
                raise ConnectorError("password expired")
            if not self.vsys_id:
                self.vsys_id = res_data["vsysId"]
            cookie = f"token={res_data['token']};username={res_data['username']};vsysId={self.vsys_id};role={res_data['role']};fromrootvsys={res_data['fromrootvsys']}"
            self._session.headers.update({"Cookie": cookie})
            self._logged = True
            logger.debug("host is %s", self.host)
        else:
            raise ConnectorError(
                "Not logged on a session, please login. Error: {0}".format(res_json)
            )

    def logout(self):
        url = self.url_prefix + "/logout"
        res = self._session.delete(url)
        self._session.close()
        self._session.cookies.clear()
        self._logged = False
        logger.info("Logout response: %s", res.text)

    def check_session(self):
        self.login()

    def request(self, method: str, endpoint: str, data=None, parameters=None):
        self.check_session()
        url = f"{self.url_prefix}/{endpoint}"
        logger.debug("data is %s", data)
        method = method.upper()
        res = self._session.request(method, url, params=parameters, json=data)
        logger.debug(f"in {method} function")
        return res

    def get_service_list(self):
        endpoint = "servicebook_service"
        params = {"isDynamic": 1}
        res = self.request("GET", endpoint, parameters=params)
        return res.json()

    def get_protocol_type_dict(self):
        endpoint = "protocolTypeList"
        res = self.request("GET", endpoint)
        logger.debug("protocolTypeList", res.json())
        return {i["name"]: i["value"] for i in res.json()["result"]}

    def get_admin_system_message(self):
        endpoint = "admind_system_message"
        params = {"currentPortlet": "systemInfoHp"}
        res = self.request("GET", endpoint, parameters=params)
        return res.json()["result"]
