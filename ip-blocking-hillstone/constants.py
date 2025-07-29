SSL_VALIDATION_ERROR = "SSL certificate validation failed"
CONNECTION_TIMEOUT = (
    "The request timed out while trying to connect to the remote server"
)
REQUEST_READ_TIMEOUT = "The server did not send any data in the allotted amount of time"
RESOURCE_NOT_FOUND = (
    "The requested resource not found on server, please check input parameters"
)
INVALID_URL_OR_CREDENTIALS = "Invalid endpoint or credentials"
UNAUTH_MSG = "Unauthorized: Wrong credentials provided. OR Check User/VSYS permission"

# API Endpoints
ADDRESS_API = "addrbook_address"
SERVICE_API = "servicebook_service"
SERVICE_GROUP_API = "servicebook_group"
POLICY_API = "policy_rule"
ZONE_API = "api/zone"

# Maximum group size
MAX_GROUP_SIZE = 500
MAX_RETRY = 5

# Address types
ADDR_TYPE_IP = 0
ADDR_TYPE_RANGE = 1
ADDR_TYPE_HOST = 2
ADDR_TYPE_WILDCARD = 3
ADDR_TYPE_COUNTRY = 4

# Protocol types
PROTOCOL_TYPES = {
    "Any": 0,
    "ICMP": 1,
    "IGMP": 2,
    "GGP": 3,
    "IPv4": 4,
    "ST": 5,
    "TCP": 6,
    "UDP": 17,
    "ip": 0,
}
