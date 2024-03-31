import json

import requests


class ZDNSClient:
    def __init__(self, config):
        self.base_url = config.get("base_url").strip()
        if not self.base_url.startswith(("https://", "http://")):
            self.base_url = "https://" + self.base_url
        self._verify = config.get("verify_ssl", False)
        self._token = ""

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
            'current_user': username,
            'search_key': search_name,
        }
        r = requests.get(url, data=params, auth=(username, password), verify=False)
        result = r.json()
        for i in result['resources']:
            if "in-addr.arpa" in str(i['name']):
                pass
            else:
                domain_dict[i['name']] = i['rdata']
        return domain_dict

    def add_rrs(self, username, password, view_name, zone_name, rrs_name, rrs_type, rrs_rdata, rrs_ttl="300",
                ptr_stat="no"):
        url = f"{self.base_url}/views/{view_name}/zones/{zone_name}/rrs"
        params = {'name': rrs_name,
                  'type': rrs_type,
                  'rdata': rrs_rdata,
                  'ttl': rrs_ttl,
                  'link_ptr': ptr_stat,
                  'current_user': username}
        headers = {'Content-type': 'application/json'}
        r = requests.post(url, data=json.dumps(params), headers=headers, auth=(username, password), verify=False)
        return r.status_code
