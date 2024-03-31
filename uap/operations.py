from integrations.crudhub import make_request

from .client.alert_client import AlertClient
from connectors.core.connector import get_logger, ConnectorError

def _check_health(config):
    try:
        ac = AlertClient(config)
        ac.alert_data("信息", "心跳检测")
    except Exception as e:
        raise ConnectorError("{}".format(e))

def send_alert(config, params):
    ac = AlertClient(config)
    res = ac.alert_data(params["issue"], params["priority"])
    return res


def get_users(config, params):
    user_list = []
    response = make_request("/api/3/people?$limit=1000", "GET")["hydra:member"]
    for user in response:
        user_list.append(
            "{} {} {}".format(user["firstname"], user["lastname"], user["email"])
        )

    return user_list
#
#
# def get_teams(config, params):
#     team_list = []
#     response = make_request("/api/3/teams?$limit=1000", "GET")["hydra:member"]
#     for team in response:
#         team_list.append(team["name"])
#
#     return team_list


operations = {"send_alert": send_alert}
