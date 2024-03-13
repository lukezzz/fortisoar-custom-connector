from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations, _check_health

logger = get_logger("f5-big-ip")


class F5LB(Connector):
    def execute(self, config, operation, params, **kwargs):
        logger.info("In execute() Operation: {}".format(operation))
        try:
            operation = operations.get(operation)
            return operation(config, params)
        except Exception as e:
            logger.exception("{}".format(e))
            raise ConnectorError("{}".format(e))

    def check_health(self, config):
        logger.info("invoke f5-big-ip check_health()")
        return _check_health(config)
