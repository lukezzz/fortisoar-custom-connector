from .make_rest_api_call import MakeRestApiCall


def add_domain(config: dict, params: dict) -> dict:
    endpoint = ""  # edit endpoint
    method = "GET"  # GET/POST/PUT/DELETE
    # write your code here, if needed.

    MK = MakeRestApiCall(config=config)
    response = MK.make_request(endpoint=endpoint, method=method, params=params)
    return response