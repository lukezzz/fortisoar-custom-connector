from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations, _check_health

logger = get_logger("qizhi_bastion")


class QiziBastionConnector(Connector):
    # def execute(self, config, operation, params, **kwargs):
    #     try:
    #         config['connector_info'] = {"connector_name": self._info_json.get('name'),
    #                                     "connector_version": self._info_json.get('version')}
    #         operation = operations.get(operation)
    #         logger.info('Action Name {}'.format(operation))
    #         if not operation:
    #             logger.error('Unsupported operation: {}'.format(operation))
    #             raise ConnectorError('Unsupported operation')
    #         return operation(config, params)
    #     except Exception as err:
    #         logger.exception(err)
    #         raise ConnectorError(err)

    def execute(self, config, operation, params, **kwargs):
        action = operations.get(operation)
        logger.info('Action Name {}'.format(action))
        try:
            return action(config, params)
        except Exception as e:
            logger.exception('{}'.format(e))
            raise ConnectorError('{}'.format(e))

    def check_health(self, config=None):
        try:
            config['connector_info'] = {"connector_name": self._info_json.get('name'),
                                        "connector_version": self._info_json.get('version')}
            return _check_health(config)
        except Exception as err:
            raise ConnectorError(err)

    def on_app_start(self, config, active):
        pass

    def on_add_config(self, config, active):
        pass

    def on_update_config(self, old_config, new_config, active):
        pass

    def on_delete_config(self, config):
        pass

    def on_activate(self, config):
        pass

    def on_deactivate(self, config):
        pass

    def teardown(self, config):
        pass
