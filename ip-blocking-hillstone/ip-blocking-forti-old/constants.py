""" Copyright start
  Copyright (C) 2008 - 2024 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

SSL_VALIDATION_ERROR = 'SSL certificate validation failed'
CONNECTION_TIMEOUT = 'The request timed out while trying to connect to the remote server'
REQUEST_READ_TIMEOUT = 'The server did not send any data in the allotted amount of time'
RESOURCE_NOT_FOUND = 'The requested resource not found on server, please check input parameters'
INVALID_URL_OR_CREDENTIALS = 'Invalid endpoint or credentials'
UNAUTH_MSG = 'Unauthorized: Wrong API key provided. OR Check User/VDOM/API key permission'  # when user don't have permission to root level that time at least 1 vdom should be specify.
WEB_PERMISSION = 'Check API key permission to access web filter.'  # when api key don't have read permission to web filter
APP_PERMISSION = 'Check API key permission to access application control.'  # when api key don't have read permission to application control

LIST_OF_POLICIES_API = '/api/v2/cmdb/firewall/policy/'
LIST_OF_SECURITY_POLICIES_API = '/api/v2/cmdb/firewall/security-policy/'
DELETE_ADDRESS = '/api/v2/cmdb/firewall/address/{ip_name}'
DELETE_IPv6_ADDRESS = '/api/v2/cmdb/firewall/address6/{ip_name}'
ADD_ADDRESS = '/api/v2/cmdb/firewall/address/'
ADD_ADDRESS_IPv6 = '/api/v2/cmdb/firewall/address6/'
ADDRESS_GROUP_API = '/api/v2/cmdb/firewall/addrgrp/{ip_group_name}'
ADDRESS_GROUP_API_IPv6 = '/api/v2/cmdb/firewall/addrgrp6/{ip_group_name}'
ADDRESS_GROUP_ALL_API = '/api/v2/cmdb/firewall/addrgrp'
ADDRESS_GROUP_ALL_API_IPv6 = '/api/v2/cmdb/firewall/addrgrp6'
GET_LIST_OF_APPLICATIONS = '/api/v2/cmdb/application/name?with_meta=1'
BLOCK_APP = '/api/v2/cmdb/application/list/{app_block_policy}'
GET_WEB_PROFILE = '/api/v2/cmdb/webfilter/profile'
URL_FILTER = '/api/v2/cmdb/webfilter/urlfilter'
LIST_VDOM = '/api/v2/cmdb/system/vdom'
BAN_IP_API = '/api/v2/monitor/user/banned/add_users'  # Block
REMOVE_BAN_API = '/api/v2/monitor/user/banned/clear_users'  # Unblock
LIST_BANNED_IPS_API = '/api/v2/monitor/user/banned/select'
QUARANTINE_HOST_API = '/api/v2/cmdb/user/quarantine'  # Quarantine/Unquarantine Host
FIREWALL_SERVICE_API = '/api/v2/cmdb/firewall.service/custom/'
FIREWALL_SERVICE_GRP_API = '/api/v2/cmdb/firewall.service/group'
COUNTRY_NAMES_API = '/api/v2/cmdb/system/geoip-country'
SYSTEM_EVENTS = '/api/v2/log/{0}/event/system'
USER_ACTIVATION_API = '/api/v2/monitor/user/fortitoken/send-activation'
USER_API = '/api/v2/cmdb/user/local/'
USER_GROUP = '/api/v2/cmdb/user/group/{group_name}'

ADDRESS_GROUP_MEMBER_API = '/api/v2/cmdb/firewall/addrgrp/{ip_group_name}/member'
ADDRESS_GROUP_MEMBER_API_IPv6 = '/api/v2/cmdb/firewall/addrgrp6/{ip_group_name}/member'
MAX_GROUP_SIZE = 600  # 300 limit for 6.0.5 version
MAX_RETRY = 5
time_to_live_values = {
    '1 Hour': 3600,
    '6 Hour': 21600,
    '12 Hour': 43200,
    '1 Day': 86400,
    '6 Months': 1.577e+7,
    '1 Year': 3.154e+7,
    'Never': 0
}

PARAM = {
    "Accept": "accept",
    "Deny": "deny",
    "IPsec": "ipsec",
    "All": "all",
    "UTM": "utm",
    "Disable": "disable",
    "Flow Based": "flow",
    "Proxy Based": "proxy",
    "Subnet": "interface-subnet",
    "IP Range": "iprange",
    "FQDN": "fqdn",
    "Geography": "geography",
    "Dynamic": "dynamic",
    "Device (MAC Address)": "mac",
    "Local User": "password",
    "Remote Radius User": "radius",
    "Remote TACACS+ User": "tacacs+"
}
security_profiles = {
    "AntiVirus": "av-profile",
    "Web Filter": "webfilter-profile",
    "DNS Filter": "dnsfilter-profile",
    "Application Control": "application-list",
    "IPS": "ips-sensor",
    "File Filter": "file-filter-profile",
    "SSL Inspection": "ssl-ssh-profile"
}

country_list = [
    {
        "id": "AD",
        "name": "Andorra"
    },
    {
        "id": "AE",
        "name": "United Arab Emirates"
    },
    {
        "id": "AF",
        "name": "Afghanistan"
    },
    {
        "id": "AG",
        "name": "Antigua and Barbuda"
    },
    {
        "id": "AI",
        "name": "Anguilla"
    },
    {
        "id": "AL",
        "name": "Albania"
    },
    {
        "id": "AM",
        "name": "Armenia"
    },
    {
        "id": "AN",
        "name": "Netherlands Antilles"
    },
    {
        "id": "AO",
        "name": "Angola"
    },
    {
        "id": "AQ",
        "name": "Antarctica"
    },
    {
        "id": "AR",
        "name": "Argentina"
    },
    {
        "id": "AS",
        "name": "American Samoa"
    },
    {
        "id": "AT",
        "name": "Austria"
    },
    {
        "id": "AU",
        "name": "Australia"
    },
    {
        "id": "AW",
        "name": "Aruba"
    },
    {
        "id": "AX",
        "name": "Aland Islands"
    },
    {
        "id": "AZ",
        "name": "Azerbaijan"
    },
    {
        "id": "BA",
        "name": "Bosnia and Herzegovina"
    },
    {
        "id": "BB",
        "name": "Barbados"
    },
    {
        "id": "BD",
        "name": "Bangladesh"
    },
    {
        "id": "BE",
        "name": "Belgium"
    },
    {
        "id": "BF",
        "name": "Burkina Faso"
    },
    {
        "id": "BG",
        "name": "Bulgaria"
    },
    {
        "id": "BH",
        "name": "Bahrain"
    },
    {
        "id": "BI",
        "name": "Burundi"
    },
    {
        "id": "BJ",
        "name": "Benin"
    },
    {
        "id": "BL",
        "name": "Saint Bartelemey"
    },
    {
        "id": "BM",
        "name": "Bermuda"
    },
    {
        "id": "BN",
        "name": "Brunei Darussalam"
    },
    {
        "id": "BO",
        "name": "Bolivia"
    },
    {
        "id": "BQ",
        "name": "Bonaire, Saint Eustatius and Saba"
    },
    {
        "id": "BR",
        "name": "Brazil"
    },
    {
        "id": "BS",
        "name": "Bahamas"
    },
    {
        "id": "BT",
        "name": "Bhutan"
    },
    {
        "id": "BV",
        "name": "Bouvet Island"
    },
    {
        "id": "BW",
        "name": "Botswana"
    },
    {
        "id": "BY",
        "name": "Belarus"
    },
    {
        "id": "BZ",
        "name": "Belize"
    },
    {
        "id": "CA",
        "name": "Canada"
    },
    {
        "id": "CC",
        "name": "Cocos (Keeling) Islands"
    },
    {
        "id": "CD",
        "name": "Congo, The Democratic Republic of the"
    },
    {
        "id": "CF",
        "name": "Central African Republic"
    },
    {
        "id": "CG",
        "name": "Congo"
    },
    {
        "id": "CH",
        "name": "Switzerland"
    },
    {
        "id": "CI",
        "name": "Cote d'Ivoire"
    },
    {
        "id": "CK",
        "name": "Cook Islands"
    },
    {
        "id": "CL",
        "name": "Chile"
    },
    {
        "id": "CM",
        "name": "Cameroon"
    },
    {
        "id": "CN",
        "name": "China"
    },
    {
        "id": "CO",
        "name": "Colombia"
    },
    {
        "id": "CR",
        "name": "Costa Rica"
    },
    {
        "id": "CU",
        "name": "Cuba"
    },
    {
        "id": "CV",
        "name": "Cape Verde"
    },
    {
        "id": "CW",
        "name": "Curacao"
    },
    {
        "id": "CX",
        "name": "Christmas Island"
    },
    {
        "id": "CY",
        "name": "Cyprus"
    },
    {
        "id": "CZ",
        "name": "Czech Republic"
    },
    {
        "id": "DE",
        "name": "Germany"
    },
    {
        "id": "DJ",
        "name": "Djibouti"
    },
    {
        "id": "DK",
        "name": "Denmark"
    },
    {
        "id": "DM",
        "name": "Dominica"
    },
    {
        "id": "DO",
        "name": "Dominican Republic"
    },
    {
        "id": "DZ",
        "name": "Algeria"
    },
    {
        "id": "EC",
        "name": "Ecuador"
    },
    {
        "id": "EE",
        "name": "Estonia"
    },
    {
        "id": "EG",
        "name": "Egypt"
    },
    {
        "id": "EH",
        "name": "Western Sahara"
    },
    {
        "id": "ER",
        "name": "Eritrea"
    },
    {
        "id": "ES",
        "name": "Spain"
    },
    {
        "id": "ET",
        "name": "Ethiopia"
    },
    {
        "id": "FI",
        "name": "Finland"
    },
    {
        "id": "FJ",
        "name": "Fiji"
    },
    {
        "id": "FK",
        "name": "Falkland Islands (Malvinas)"
    },
    {
        "id": "FM",
        "name": "Micronesia, Federated States of"
    },
    {
        "id": "FO",
        "name": "Faroe Islands"
    },
    {
        "id": "FR",
        "name": "France"
    },
    {
        "id": "GA",
        "name": "Gabon"
    },
    {
        "id": "GB",
        "name": "United Kingdom"
    },
    {
        "id": "GD",
        "name": "Grenada"
    },
    {
        "id": "GE",
        "name": "Georgia"
    },
    {
        "id": "GF",
        "name": "French Guiana"
    },
    {
        "id": "GG",
        "name": "Guernsey"
    },
    {
        "id": "GH",
        "name": "Ghana"
    },
    {
        "id": "GI",
        "name": "Gibraltar"
    },
    {
        "id": "GL",
        "name": "Greenland"
    },
    {
        "id": "GM",
        "name": "Gambia"
    },
    {
        "id": "GN",
        "name": "Guinea"
    },
    {
        "id": "GP",
        "name": "Guadeloupe"
    },
    {
        "id": "GQ",
        "name": "Equatorial Guinea"
    },
    {
        "id": "GR",
        "name": "Greece"
    },
    {
        "id": "GS",
        "name": "South Georgia and the South Sandwich Islands"
    },
    {
        "id": "GT",
        "name": "Guatemala"
    },
    {
        "id": "GU",
        "name": "Guam"
    },
    {
        "id": "GW",
        "name": "Guinea-Bissau"
    },
    {
        "id": "GY",
        "name": "Guyana"
    },
    {
        "id": "HK",
        "name": "Hong Kong"
    },
    {
        "id": "HM",
        "name": "Heard Island and McDonald Islands"
    },
    {
        "id": "HN",
        "name": "Honduras"
    },
    {
        "id": "HR",
        "name": "Croatia"
    },
    {
        "id": "HT",
        "name": "Haiti"
    },
    {
        "id": "HU",
        "name": "Hungary"
    },
    {
        "id": "ID",
        "name": "Indonesia"
    },
    {
        "id": "IE",
        "name": "Ireland"
    },
    {
        "id": "IL",
        "name": "Israel"
    },
    {
        "id": "IM",
        "name": "Isle of Man"
    },
    {
        "id": "IN",
        "name": "India"
    },
    {
        "id": "IO",
        "name": "British Indian Ocean Territory"
    },
    {
        "id": "IQ",
        "name": "Iraq"
    },
    {
        "id": "IR",
        "name": "Iran, Islamic Republic of"
    },
    {
        "id": "IS",
        "name": "Iceland"
    },
    {
        "id": "IT",
        "name": "Italy"
    },
    {
        "id": "JE",
        "name": "Jersey"
    },
    {
        "id": "JM",
        "name": "Jamaica"
    },
    {
        "id": "JO",
        "name": "Jordan"
    },
    {
        "id": "JP",
        "name": "Japan"
    },
    {
        "id": "KE",
        "name": "Kenya"
    },
    {
        "id": "KG",
        "name": "Kyrgyzstan"
    },
    {
        "id": "KH",
        "name": "Cambodia"
    },
    {
        "id": "KI",
        "name": "Kiribati"
    },
    {
        "id": "KM",
        "name": "Comoros"
    },
    {
        "id": "KN",
        "name": "Saint Kitts and Nevis"
    },
    {
        "id": "KP",
        "name": "Korea, Democratic People's Republic of"
    },
    {
        "id": "KR",
        "name": "Korea, Republic of"
    },
    {
        "id": "KW",
        "name": "Kuwait"
    },
    {
        "id": "KY",
        "name": "Cayman Islands"
    },
    {
        "id": "KZ",
        "name": "Kazakhstan"
    },
    {
        "id": "LA",
        "name": "Lao People's Democratic Republic"
    },
    {
        "id": "LB",
        "name": "Lebanon"
    },
    {
        "id": "LC",
        "name": "Saint Lucia"
    },
    {
        "id": "LI",
        "name": "Liechtenstein"
    },
    {
        "id": "LK",
        "name": "Sri Lanka"
    },
    {
        "id": "LR",
        "name": "Liberia"
    },
    {
        "id": "LS",
        "name": "Lesotho"
    },
    {
        "id": "LT",
        "name": "Lithuania"
    },
    {
        "id": "LU",
        "name": "Luxembourg"
    },
    {
        "id": "LV",
        "name": "Latvia"
    },
    {
        "id": "LY",
        "name": "Libyan Arab Jamahiriya"
    },
    {
        "id": "MA",
        "name": "Morocco"
    },
    {
        "id": "MC",
        "name": "Monaco"
    },
    {
        "id": "MD",
        "name": "Moldova, Republic of"
    },
    {
        "id": "ME",
        "name": "Montenegro"
    },
    {
        "id": "MF",
        "name": "Saint Martin"
    },
    {
        "id": "MG",
        "name": "Madagascar"
    },
    {
        "id": "MH",
        "name": "Marshall Islands"
    },
    {
        "id": "MK",
        "name": "Macedonia"
    },
    {
        "id": "ML",
        "name": "Mali"
    },
    {
        "id": "MM",
        "name": "Myanmar"
    },
    {
        "id": "MN",
        "name": "Mongolia"
    },
    {
        "id": "MO",
        "name": "Macao"
    },
    {
        "id": "MP",
        "name": "Northern Mariana Islands"
    },
    {
        "id": "MQ",
        "name": "Martinique"
    },
    {
        "id": "MR",
        "name": "Mauritania"
    },
    {
        "id": "MS",
        "name": "Montserrat"
    },
    {
        "id": "MT",
        "name": "Malta"
    },
    {
        "id": "MU",
        "name": "Mauritius"
    },
    {
        "id": "MV",
        "name": "Maldives"
    },
    {
        "id": "MW",
        "name": "Malawi"
    },
    {
        "id": "MX",
        "name": "Mexico"
    },
    {
        "id": "MY",
        "name": "Malaysia"
    },
    {
        "id": "MZ",
        "name": "Mozambique"
    },
    {
        "id": "NA",
        "name": "Namibia"
    },
    {
        "id": "NC",
        "name": "New Caledonia"
    },
    {
        "id": "NE",
        "name": "Niger"
    },
    {
        "id": "NF",
        "name": "Norfolk Island"
    },
    {
        "id": "NG",
        "name": "Nigeria"
    },
    {
        "id": "NI",
        "name": "Nicaragua"
    },
    {
        "id": "NL",
        "name": "Netherlands"
    },
    {
        "id": "NO",
        "name": "Norway"
    },
    {
        "id": "NP",
        "name": "Nepal"
    },
    {
        "id": "NR",
        "name": "Nauru"
    },
    {
        "id": "NU",
        "name": "Niue"
    },
    {
        "id": "NZ",
        "name": "New Zealand"
    },
    {
        "id": "O1",
        "name": "Other Country"
    },
    {
        "id": "OM",
        "name": "Oman"
    },
    {
        "id": "PA",
        "name": "Panama"
    },
    {
        "id": "PE",
        "name": "Peru"
    },
    {
        "id": "PF",
        "name": "French Polynesia"
    },
    {
        "id": "PG",
        "name": "Papua New Guinea"
    },
    {
        "id": "PH",
        "name": "Philippines"
    },
    {
        "id": "PK",
        "name": "Pakistan"
    },
    {
        "id": "PL",
        "name": "Poland"
    },
    {
        "id": "PM",
        "name": "Saint Pierre and Miquelon"
    },
    {
        "id": "PN",
        "name": "Pitcairn"
    },
    {
        "id": "PR",
        "name": "Puerto Rico"
    },
    {
        "id": "PS",
        "name": "Palestinian Territory"
    },
    {
        "id": "PT",
        "name": "Portugal"
    },
    {
        "id": "PW",
        "name": "Palau"
    },
    {
        "id": "PY",
        "name": "Paraguay"
    },
    {
        "id": "QA",
        "name": "Qatar"
    },
    {
        "id": "RE",
        "name": "Reunion"
    },
    {
        "id": "RO",
        "name": "Romania"
    },
    {
        "id": "RS",
        "name": "Serbia"
    },
    {
        "id": "RU",
        "name": "Russian Federation"
    },
    {
        "id": "RW",
        "name": "Rwanda"
    },
    {
        "id": "SA",
        "name": "Saudi Arabia"
    },
    {
        "id": "SB",
        "name": "Solomon Islands"
    },
    {
        "id": "SC",
        "name": "Seychelles"
    },
    {
        "id": "SD",
        "name": "Sudan"
    },
    {
        "id": "SE",
        "name": "Sweden"
    },
    {
        "id": "SG",
        "name": "Singapore"
    },
    {
        "id": "SH",
        "name": "Saint Helena"
    },
    {
        "id": "SI",
        "name": "Slovenia"
    },
    {
        "id": "SJ",
        "name": "Svalbard and Jan Mayen"
    },
    {
        "id": "SK",
        "name": "Slovakia"
    },
    {
        "id": "SL",
        "name": "Sierra Leone"
    },
    {
        "id": "SM",
        "name": "San Marino"
    },
    {
        "id": "SN",
        "name": "Senegal"
    },
    {
        "id": "SO",
        "name": "Somalia"
    },
    {
        "id": "SR",
        "name": "Suriname"
    },
    {
        "id": "SS",
        "name": "South Sudan"
    },
    {
        "id": "ST",
        "name": "Sao Tome and Principe"
    },
    {
        "id": "SV",
        "name": "El Salvador"
    },
    {
        "id": "SX",
        "name": "Sint Maarten"
    },
    {
        "id": "SY",
        "name": "Syrian Arab Republic"
    },
    {
        "id": "SZ",
        "name": "Swaziland"
    },
    {
        "id": "TC",
        "name": "Turks and Caicos Islands"
    },
    {
        "id": "TD",
        "name": "Chad"
    },
    {
        "id": "TF",
        "name": "French Southern Territories"
    },
    {
        "id": "TG",
        "name": "Togo"
    },
    {
        "id": "TH",
        "name": "Thailand"
    },
    {
        "id": "TJ",
        "name": "Tajikistan"
    },
    {
        "id": "TK",
        "name": "Tokelau"
    },
    {
        "id": "TL",
        "name": "Timor-Leste"
    },
    {
        "id": "TM",
        "name": "Turkmenistan"
    },
    {
        "id": "TN",
        "name": "Tunisia"
    },
    {
        "id": "TO",
        "name": "Tonga"
    },
    {
        "id": "TR",
        "name": "Turkey"
    },
    {
        "id": "TT",
        "name": "Trinidad and Tobago"
    },
    {
        "id": "TV",
        "name": "Tuvalu"
    },
    {
        "id": "TW",
        "name": "Taiwan"
    },
    {
        "id": "TZ",
        "name": "Tanzania, United Republic of"
    },
    {
        "id": "UA",
        "name": "Ukraine"
    },
    {
        "id": "UG",
        "name": "Uganda"
    },
    {
        "id": "UM",
        "name": "United States Minor Outlying Islands"
    },
    {
        "id": "US",
        "name": "United States"
    },
    {
        "id": "UY",
        "name": "Uruguay"
    },
    {
        "id": "UZ",
        "name": "Uzbekistan"
    },
    {
        "id": "VA",
        "name": "Holy See (Vatican City State)"
    },
    {
        "id": "VC",
        "name": "Saint Vincent and the Grenadines"
    },
    {
        "id": "VE",
        "name": "Venezuela"
    },
    {
        "id": "VG",
        "name": "Virgin Islands, British"
    },
    {
        "id": "VI",
        "name": "Virgin Islands, U.S."
    },
    {
        "id": "VN",
        "name": "Vietnam"
    },
    {
        "id": "VU",
        "name": "Vanuatu"
    },
    {
        "id": "WF",
        "name": "Wallis and Futuna"
    },
    {
        "id": "WS",
        "name": "Samoa"
    },
    {
        "id": "XK",
        "name": "Kosovo"
    },
    {
        "id": "YE",
        "name": "Yemen"
    },
    {
        "id": "YT",
        "name": "Mayotte"
    },
    {
        "id": "ZA",
        "name": "South Africa"
    },
    {
        "id": "ZM",
        "name": "Zambia"
    },
    {
        "id": "ZW",
        "name": "Zimbabwe"
    },
    {
        "id": "ZZ",
        "name": "Reserved"
    }
]
