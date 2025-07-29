import requests
from requests.adapters import HTTPAdapter, Retry
from urllib.parse import urlparse

from connectors.core.connector import get_logger, ConnectorError

logger = get_logger("yunke-lb")


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


class YunkeClient:
    def __init__(self, config, host, username, password, port=10443):

        super().__init__()

        self.base_url = host if host else config.get("server_url").strip()
        if not self.base_url.startswith(("https://", "http://")):
            self.base_url = "https://" + self.base_url

        # Store port and add to URL if specified
        self.port = port
        if port:
            # Parse existing URL to avoid duplicate ports
            parsed_url = urlparse(self.base_url)
            if not parsed_url.port:  # Only add port if not already present
                self.base_url = f"{self.base_url}:{port}"

        self._verify = config.get("verify_ssl")
        self.username = username
        self.password = password
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "FortiSOAR",
        }

        self._logged = False
        self._session = requests.Session()
        self._session.verify = config.get("verify_ssl")

        retries = Retry(
            total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504]
        )
        self._session.mount("http://", TimeoutHTTPAdapter(max_retries=retries))
        self._session.mount("https://", TimeoutHTTPAdapter(max_retries=retries))

    def login(self):
        if not self._logged:
            login_url = self.base_url + "/adc/v3.0/login"
            payload = {
                "username": self.username,
                "password": self.password,
            }
            response = self._session.post(login_url, json=payload, headers=self.headers)
            if response.status_code == 200:
                # update headers with login token
                response_data = response.json()
                token = response_data.get("data", {}).get("token")
                if not token:
                    raise ConnectorError("Login failed: Token not found in response")
                self.headers["x-access-token"] = token
                self._logged = True
                logger.info("Login successful")
            else:
                raise ConnectorError(f"Login failed: {response.text}")

    def logout(self):
        if self._logged:
            logout_url = self.base_url + "/adc/v3.0/logout/" + self.username
            response = self._session.delete(logout_url, headers=self.headers)
            if response.status_code == 200:
                self._logged = False
                logger.info("Logout successful")
            else:
                logger.error(f"Logout failed: {response.text}")
        else:
            logger.warning("Not logged in, no action taken on logout")

    def run(self, endpoint, method="GET", data=None) -> requests.Response:

        if not self._logged:
            self.login()

        url = self.base_url + endpoint

        if method == "POST":
            response = self._session.post(url, json=data, headers=self.headers)
        else:
            response = self._session.get(url, params=data, headers=self.headers)

        return response
