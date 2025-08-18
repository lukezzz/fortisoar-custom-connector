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
        self.vsys_id = config.get("vsys_id", 0)

        self.username = base64.b64encode(username.encode()).decode()
        self.raw_username = username
        self.password = base64.b64encode(password.encode()).decode()
        self._logged = False

        self._session = requests.Session()
        self._session.verify = config.get("verify_ssl", False)
        retries = Retry(
            total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504]
        )
        self._session.mount("http://", TimeoutHTTPAdapter(max_retries=retries))
        self._session.mount("https://", TimeoutHTTPAdapter(max_retries=retries))

        self.url_prefix = f"https://{self.host}/rest"
        self.use_old_api = config.get("use_old_api", False)

    def login(self, is_api_login=True):
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
        res = self._session.post(url, json=login_data, verify=self._session.verify)
        res_json = res.json()
        logger.debug("Login response JSON: %s", res_json)
        if res_json["success"]:
            res_data = (
                res_json["result"][0]
                if isinstance(res_json["result"], list)
                else res_json["result"]
            )
            if res_data.get("passwordExpired") == 1:
                raise ConnectorError("password expired")
            self.vsys_id = res_data["vsysId"]

            if self.use_old_api:
                cookie = f"token={res_data['token']};username={self.raw_username};vsysId={self.vsys_id};role={res_data['role']};fromrootvsys={res_data['fromrootvsys']}"
                self._session.headers.update({"Cookie": cookie})
            else:
                api_headers = {
                    "X-Api-Language": "en",
                    "X-Auth-Role": res_data["role"],
                    "X-Auth-Token": res_data["token"],
                    "X-Auth-Vsysid": str(self.vsys_id),
                    "Content-Type": "application/json",
                    "X-Auth-Username": res_data["username"],
                    "X-Auth-Fromrootvsys": str(res_data["fromrootvsys"]).lower(),
                }
                self._session.headers.update(api_headers)
            self._logged = True
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
        logger.debug("Checking session", self._logged)
        if not self._logged:
            self.login()
        # Optionally, you can add a session validation check here
        # by making a simple API call to verify the session is still valid

    def request(self, method: str, endpoint: str, data=None, parameters=None):
        self.check_session()  # Use check_session instead of login to avoid re-logging in

        # Remove leading slash from endpoint if present to avoid double slash in URL
        if endpoint.startswith("/"):
            endpoint = endpoint[1:]

        url = f"{self.url_prefix}/{endpoint}"
        method = method.upper()

        logger.debug(f"Making {method} request to: {url}")
        logger.debug(f"Request headers: {dict(self._session.headers)}")

        if method == "GET":
            res = self._session.request(method, url, params=parameters)
        else:
            res = self._session.request(method, url, json=data)

        logger.debug(f"Response status: {res.status_code}")
        logger.debug(f"Response text: {res.text[:500]}...")  # Log first 500 chars

        return res

    def get_sysinfo(self):
        endpoint = "api/sysinfo"
        res = self.request("GET", endpoint)
        return res.json()["result"]

    def test_create_address_object(self, name, ip_addr, netmask="32", is_ipv6="0"):
        """Create an address object using the API"""
        endpoint = "api/addrbook?nodeOption=1"
        payload = [
            {
                "name": name,
                "is_ipv6": is_ipv6,
                "ip": [{"ip_addr": ip_addr, "netmask": netmask, "flag": "0"}],
                "predefined": "0",
            }
        ]
        res = self.request("POST", endpoint, data=payload)
        return res

    def test_session(self):
        """Test if the current session is valid by making a simple API call"""
        try:
            if not self._logged:
                return False, "Not logged in"

            # Make a simple API call to test session validity
            res = self.get_sysinfo()
            return True, "Session is valid"
        except Exception as e:
            return False, f"Session test failed: {str(e)}"
