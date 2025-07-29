from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations, _check_health

logger = get_logger("yunke-lb")


class YunkeLB(Connector):
    def execute(self, config, operation, params, **kwargs):
        logger.info("In execute() Operation: {}".format(operation))
        try:
            operation = operations.get(operation)
            return operation(config, params)
        except Exception as e:
            logger.exception("{}".format(e))
            raise ConnectorError("{}".format(e))

    def check_health(self, config):
        logger.info("invoke yunke-lb check_health()")
        return _check_health(config)
