from connectors.core.connector import Connector
from connectors.core.connector import get_logger, ConnectorError
from .constants import *
from .operations import get_account_list,  operations
logger = get_logger("bitdefender")


class Bitdefender(Connector):
    def execute(self, config, operation, params, *args, **kwargs):
        try:
            action = operations.get(operation)
            logger.info("executing action {0}".format(action))
            return action(config, params)
        except Exception as e:
            logger.exception(str(e))
            raise ConnectorError(str(e))

    def check_health(self, config=None, *args, **kwargs):
        token = "Basic " + config.get("url")
        return get_account_list(config.get("url"), token)
