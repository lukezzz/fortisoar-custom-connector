# -----------------------------------------
#  CiscoCatalyst
# -----------------------------------------
# Integration connector imports
from connectors.core.connector import Connector
from .operations import operations, _check_health


class CiscoCatalyst(Connector):
    def execute(self, config, operation, params, **kwargs):
        action = operations.get(operation)
        return action(config, params)

    def check_health(self, config):
        return _check_health(config)
