from connectors.core.connector import get_logger, ConnectorError
from requests.adapters import HTTPAdapter, Retry
import requests
import six.moves.urllib as urllib
import json

try:
    import urllib.parse as urlencoding
except:
    import urllib as urlencoding

logger = get_logger("fortigate-fw")


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


class FortiGateFWClient:
    def __init__(self, config, username, password):

        self.host = config.get("url")
        self.vdom = config.get("vdom") if config.get("vdom") else "root"
        self._fortiversion = "Version is set when logged"

        self.username = username
        self.password = password
        self._logged = False

        self._session = requests.Session()
        self._session.verify = config.get("verify_ssl")
        retries = Retry(
            total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504]
        )
        self._session.mount("http://", TimeoutHTTPAdapter(max_retries=retries))
        self._session.mount("https://", TimeoutHTTPAdapter(max_retries=retries))

        self.url_prefix = None

    def update_cookie(self):
        # Retrieve server csrf and update session's headers
        logger.debug("cookies are  : %s ", self._session.cookies)
        for cookie in self._session.cookies:
            if cookie.name == "ccsrftoken" or cookie.name.startswith('ccsrftoken_'):
                csrftoken = cookie.value[1:-1]  # token stored as a list
                logger.debug("csrftoken before update  : %s ", csrftoken)
                self._session.headers.update({"X-CSRFTOKEN": csrftoken})
                logger.debug("csrftoken after update  : %s ", csrftoken)
        logger.debug("New session header is: %s", self._session.headers)

    def login(self, host=None, vdom=None):
        logger.debug("Logging in to FortiGate")
        if vdom:
            self.vdom = vdom
        if host:
            self.host = host
        self.url_prefix = f"https://{self.host}"
        url = f"{self.url_prefix}/logincheck"
        res = self._session.post(
            url,
            data="username="
            + urllib.parse.quote(self.username)
            + "&secretkey="
            + urllib.parse.quote(self.password)
            + "&ajax=1",
        )
        logger.debug("Login response: %s", res.text)
        if res.content.decode("ascii")[0] == "1":
            # Update session's csrftoken
            self.update_cookie()
            self._logged = True
            logger.debug("host is %s", self.host)
            param = "{ vdom = " + self.vdom + " }"
            resp_lic = self.monitor("license/status", parameters=param)
            logger.debug("response system/status : %s", resp_lic)
            try:
                self._fortiversion = resp_lic["version"]
                return True
            except KeyError:
                if resp_lic["status"] == "success":
                    self._logged = True
                    return True
                else:
                    self._logged = False
                    raise ConnectorError("Not logged on a session, please login")

    def logout(self):

        url = self.url_prefix + "/logout"
        res = self._session.post(url)
        self._session.close()
        self._session.cookies.clear()
        self._logged = False
        logger.info("Logout response: %s", res.text)

    def check_session(self):

        if not self._logged:
            raise ConnectorError("Not logged on a session, please login")

    def formatresponse(self, res):
        logger.debug("formating response")

        try:
            if self.vdom == "global":
                resp = json.loads(res.content.decode("utf-8"))[0]
                resp["vdom"] = "global"
            else:
                logger.debug("content res: %s", res.content)
                resp = json.loads(res.content.decode("utf-8"))
            return resp
        except:
            # that means res.content does not exist (error in general)
            # in that case return raw result TODO fix that with a loop in case of global
            logger.warning(
                "in formatresponse res.content does not exist, should not occur"
            )
            return res

    def render_url(self, url, mkey=None):
        if mkey:
            url = url + "/" + urlencoding.quote(str(mkey), safe="")
        if self.vdom:
            logger.debug("vdom is: %s", self.vdom)
            if self.vdom == "global":
                url += "?global=1"
            else:
                url += "?vdom=" + self.vdom
        return url

    def monitor(self, endpoint, mkey=None, parameters=None):
        self.check_session()
        # return builded URL
        url = self.url_prefix + f"/api/v2/monitor/{endpoint}"

        url = self.render_url(url, mkey)
        logger.debug("in monitor url is %s", url)
        res = self._session.get(url, params=parameters)
        logger.debug("in MONITOR function")
        return self.formatresponse(res)

    def get(self, endpoint, mkey=None, parameters=None):
        self.check_session()
        url = self.url_prefix + f"/api/v2/cmdb/{endpoint}"
        url = self.render_url(url, mkey)

        logger.debug("Calling GET ( %s, %s)", url, parameters)
        res = self._session.get(url, params=parameters)
        logger.debug("in GET function")
        return self.formatresponse(res)

    def post(self, endpoint, mkey=None, data=None, parameters=None):
        self.check_session()
        url = self.url_prefix + f"/api/v2/cmdb/{endpoint}"
        url = self.render_url(url, mkey)
        logger.debug("Calling POST ( %s)", url)
        logger.debug("data is %s", data)
        res = self._session.post(url, params=parameters, json=data)
        logger.debug("in POST function")
        return self.formatresponse(res)

    def set(self, endpoint, mkey=None, data=None, parameters=None):
        self.check_session()
        url = self.url_prefix + f"/api/v2/cmdb/{endpoint}"
        url = self.render_url(url, mkey)
        logger.debug("Calling SET ( %s)", url)
        logger.debug("data is %s", data)
        res = self._session.put(url, params=parameters, data=json.dumps(data))
        logger.debug("in SET function after PUT")
        r = self.formatresponse(res)

        if (
            r["http_status"] == 404
            or r["http_status"] == 405
            or r["http_status"] == 500
        ):
            logger.warning(
                "Try to put on %s  failed doing a put to force parameters\
                change consider delete if still fails ",
                res.request.url,
            )
            res = self.post(endpoint, mkey, data)
            logger.debug("in SET function after POST result %s", res)
            return self.formatresponse(res)
        else:
            return r
