from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations, _check_health

logger = get_logger("fortigate-fw")


class FortinetFW(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            logger.info("In execute() Operation: {}".format(operation))
            operation = operations.get(operation)
            return operation(config, params)
        except Exception as e:
            logger.error(
                "Error in Operation:[{0}] \n{1}".format(operation.__name__, str(e))
            )
            raise ConnectorError(e)

    def check_health(self, config):
        try:
            return _check_health(config)
        except Exception as e:
            raise ConnectorError(e)
