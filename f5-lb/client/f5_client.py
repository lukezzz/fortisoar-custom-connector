import requests
from requests.adapters import HTTPAdapter, Retry

from connectors.core.connector import get_logger, ConnectorError

logger = get_logger("f5-big-ip")


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


class F5Client:
    def __init__(self, config, host, username, password):

        super().__init__()

        self.base_url = host if host else config.get("server_url").strip()
        if not self.base_url.startswith(("https://", "http://")):
            self.base_url = "https://" + self.base_url
        self._verify = config.get("verify_ssl")
        self.username = username
        self.password = password
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "User-Agent": "FortiSOAR",
        }

    def prepare_session(self) -> requests.Session:
        session = requests.Session()
        session.auth = (self.username, self.password)
        session.headers.update(self.headers)
        session.verify = bool(self._verify)

        retries = Retry(
            total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504]
        )
        session.mount("http://", TimeoutHTTPAdapter(max_retries=retries))
        session.mount("https://", TimeoutHTTPAdapter(max_retries=retries))

        return session

    def run(self, endpoint, method="GET", data=None) -> requests.Response:

        session = self.prepare_session()

        url = self.base_url + endpoint

        if method == "POST":
            response = session.post(url, json=data)
        else:
            response = session.get(url, params=data)

        return response
