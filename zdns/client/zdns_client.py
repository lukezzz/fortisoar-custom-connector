import json
from connectors.core.connector import get_logger
import requests

logger = get_logger("zdns")


class ZDNSClient:
    def __init__(self, config):
        self.base_url = config.get("base_url").strip()
        if not self.base_url.startswith(("https://", "http://")):
            self.base_url = "https://" + self.base_url
        self._verify = config.get("verify_ssl", False)
        self._token = ""
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "*/*",
            "Connection": "keep-alive",
        }

    def get_zone_list(self, username: str, password: str, view_name: str):
        zone_list = []
        url = f"{self.base_url}/views/{view_name}/zones"
        params = {"current_user": username}
        r = requests.get(
            url, data=params, auth=(username, password), verify=self._verify
        )
        result = r.json()
        for i in result["resources"]:
            zone_list.append(str(i["name"]))
        return zone_list

    def find_domain(self, username, password, search_name):
        url = f"{self.base_url}/dns-search-resources"
        domain_dict = {}
        params = {
            "current_user": username,
            "search_key": search_name,
        }
        r = requests.get(
            url, data=params, auth=(username, password), verify=self._verify
        )
        result = r.json()

        # Normalize search_name to ensure it ends with a dot for exact matching
        if not search_name.endswith("."):
            search_name_with_dot = search_name + "."
        else:
            search_name_with_dot = search_name

        for record in result["resources"]:
            # Skip reverse DNS entries
            if "in-addr.arpa" in str(record["name"]):
                continue

            # Only include exact matches for the domain name
            if record["name"] == search_name_with_dot or record["name"] == search_name:
                domain_name = record["name"]

                # If this is the first record for this domain, create a list
                if domain_name not in domain_dict:
                    domain_dict[domain_name] = []

                # Add the complete record information
                domain_dict[domain_name].append(record)

        return domain_dict

    def add_rrs(
        self,
        username,
        password,
        view_name,
        zone_name,
        rrs_name,
        rrs_type,
        rrs_rdata,
        rrs_ttl="300",
        ptr_stat="no",
    ):
        url = f"{self.base_url}/views/{view_name}/zones/{zone_name}/rrs"
        params = {
            "name": rrs_name,
            "type": rrs_type,
            "rdata": rrs_rdata,
            "ttl": rrs_ttl,
            "link_ptr": ptr_stat,
            "current_user": username,
        }
        headers = {"Content-type": "application/json"}
        r = requests.post(
            url,
            data=json.dumps(params),
            headers=self.headers,
            auth=(username, password),
            verify=False,
        )
        return r

    def create_gmember(self, username, password, dc_name, gmember_name, ip, port):
        """
        Create a gmember in a specific DC
        """
        url = f"{self.base_url}/dc/{dc_name}/gmember"
        payload = {
            "gmember_name": gmember_name,
            "ip": ip,
            "port": str(port),  # Ensure port is an str
            "hms": [],
            "linkid": "",
            "preferred": "",
            "alternate": "",
            "enable": "yes",
        }

        r = requests.post(
            url,
            data=json.dumps(payload),
            headers=self.headers,
            auth=(username, password),
            verify=self._verify,
        )
        logger.info(f"Create gmember response: {r.status_code} - {r.text}")
        return r

    def create_gpool(self, username, password, gpool_name, gmembers):
        """
        Create a gpool with specified gmembers
        gmembers should be a list of dicts with keys: dc_name, gmember_name, ratio, enable
        """
        url = f"{self.base_url}/gpool"

        gmember_list = []
        for gm in gmembers:
            gmember_list.append(
                {
                    "dc_name": gm["dc_name"],
                    "gmember_name": gm["gmember_name"],
                    "ratio": gm.get("ratio", 1),
                    "enable": gm.get("enable", "yes"),
                }
            )

        payload = {
            "name": gpool_name,
            "ttl": "10",
            "type": "A",
            "max_addr_ret": "1",
            "hm_gm_flag": "yes",
            "hms": [],
            "hm_gool_flag": "no",
            "warning": "yes",
            "first_algorithm": "sp",
            "second_algorithm": "none",
            "gmember_list": gmember_list,
            "enable": "yes",
        }

        r = requests.post(
            url,
            data=json.dumps(payload),
            headers=self.headers,
            auth=(username, password),
            verify=self._verify,
        )
        return r

    def create_dzone(self, username, password, dzone_name, gpool_name):
        """
        Create a dzone (DNS zone) mapping to a gpool
        """
        # Determine domain based on dzone_name
        if "fullgoal.com.cn" in dzone_name:
            domain_name = "fullgoal.com.cn."
        else:
            domain_name = "fuguo."

        url = f"{self.base_url}/views/ADD/dzone/{domain_name}/gmap"

        payload = {
            "name": dzone_name.split(".")[0],
            "type": "A",
            "algorithm": "rr",
            "gpool_list": [{"id": "_id6", "gpool_name": gpool_name, "ratio": "1"}],
            "last_resort_pool": "",
            "fail_policy": "return_to_dns",
            "enable": "yes",
        }

        r = requests.post(
            url,
            data=json.dumps(payload),
            headers=self.headers,
            auth=(username, password),
            verify=self._verify,
        )
        return r
