import requests
from requests.adapters import HTTPAdapter, Retry
import ssl

from connectors.core.connector import get_logger, ConnectorError

logger = get_logger("cisco-nxapi")


class TimeoutHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self.timeout = 300  # for slow nxapi commands
        if "timeout" in kwargs:
            self.timeout = kwargs["timeout"]
            del kwargs["timeout"]
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        timeout = kwargs.get("timeout")
        if timeout is None:
            kwargs["timeout"] = self.timeout
        return super().send(request, **kwargs)


class SSLAdapter(HTTPAdapter):

    def init_poolmanager(self, *args, **kwargs):

        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1

        kwargs["ssl_context"] = ssl_context
        return super().init_poolmanager(*args, **kwargs)


class CiscoNXAPIClient:
    def __init__(self, config, params):

        super().__init__()

        self.base_url = (
            params.get("hostname")
            if params.get("hostname")
            else config.get("server_url").strip()
        )
        if not self.base_url.startswith(("https://", "http://")):
            self.base_url = "https://" + self.base_url
        self._verify = config.get("verify_ssl") if config.get("verify_ssl") else False
        self.username = params.get("username")
        self.password = params.get("password")
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "FortiSOAR",
        }

    def prepare_session(self) -> requests.Session:
        session = requests.Session()
        session.auth = (self.username, self.password)
        session.headers.update(self.headers)
        session.verify = False

        retries = Retry(
            total=1, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504]
        )
        session.mount("http://", TimeoutHTTPAdapter(max_retries=retries))
        session.mount("https://", SSLAdapter(max_retries=retries))

        return session

    def nxapi_send_cmd(self, params) -> requests.Response:

        session = self.prepare_session()

        commands = " ; ".join(params.get("commands"))

        data = {
            "ins_api": {
                "version": "1.0",
                "type": "cli_conf",
                "chunk": "0",
                "sid": "1",
                "input": commands,
                "output_format": "json",
            }
        }

        url = self.base_url + "/ins"

        try:
            response = session.post(url, json=data)
        except Exception as e:
            # If HTTPS fails due to SSL Error, try HTTP
            if self.base_url.startswith("https://"):
                self.base_url = "http://" + self.base_url[8:]
            else:
                self.base_url = "http://" + self.base_url
            url = self.base_url + "/ins"
            response = session.post(url, json=data)

        # verify the response, 1. status code, 2. response body content
        if response.status_code != 200:
            raise ConnectorError(
                f"Failed to execute the command on the device. Status code: {response.status_code}, Response: {response.text}"
            )

        response_json = response.json()
        if "ins_api" not in response_json:
            raise ConnectorError(
                f"Failed to execute the command on the device. Response: {response.text}"
            )

        return response
