from connectors.core.connector import Connector, get_logger, ConnectorError

logger = get_logger("paloalto-firewall")


class PaloAltoCustomConnector(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            api_type = config.get("api_type")
            if api_type == "XML APIs":
                from .xml_api_actions import operations
            else:
                from .operations import operations
            action = operations.get(operation)
            logger.info("executing action {0}".format(action))
            return action(config, params)
        except Exception as e:
            logger.exception(str(e))
            raise ConnectorError(str(e))

    def check_health(self, config):
        pass
