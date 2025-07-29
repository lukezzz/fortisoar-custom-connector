DEL_ADDR_GRP_XPATH = "/static/member[text()='{address_name}']"
URL_PROF_ELEM = "<list><member>{url}</member></list>"
DEL_URL_XPATH = "/list/member[text()='{url}']"

VSYS_NAME = "vsys1"

HEALTH_CHECK_XPATH = (
    "/config/devices/entry/vsys/entry[@name='{vsys_name}']/rulebase/security"
)

URL_XPATH = (
    "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys_name}']/profiles/"
    "custom-url-category/entry[@name='{url_profile_name}']"
)

APPLICATION_XPATH = (
    "/config/devices/entry[@name='localhost.localdomain']/vsys/entry"
    "[@name='{vsys_name}']/application-group/entry[@name='{app_group_name}']"
)

IP_XPATH_GROUP = (
    "/config/devices/entry[@name='localhost.localdomain']/vsys/entry"
    "[@name='{vsys_name}']/address-group/entry[@name='{address_group}']"
)

IP_ADDRESS_XPATH = (
    "/config/devices/entry[@name='localhost.localdomain']/vsys/entry"
    "[@name='{vsys_name}']/address/entry[@name='{address_name}']"
)

ADDRESS_TYPE = {
    "IP Netmask": "ip-netmask",
    "IP Range": "ip-range",
    "IP Wildcard": "ip-wildcard",
    "FQDN": "fqdn",
}

ADDRESS_GROUP = {"Static": "member", "Dynamic": "filter"}

POLICY_ACTION = {
    "Deny": "deny",
    "Allow": "allow",
    "Drop": "drop",
    "Reset Client": "reset-client",
    "Reset Server": "reset-server",
    "Reset Both": "reset-both",
}
