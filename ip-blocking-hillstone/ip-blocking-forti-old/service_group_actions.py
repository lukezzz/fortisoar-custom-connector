""" Copyright start
  Copyright (C) 2008 - 2024 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import get_logger, ConnectorError

from .utils import *
from .utils import _validate_vdom, _api_request, _get_list_from_str_or_list

logger = get_logger('fortigate-firewall')


def is_service_available(config, service_name, vdom_list):
    try:
        res = _api_request(config, '{0}/{1}'.format(FIREWALL_SERVICE_API, service_name,
                                                    parameters={'vdom': vdom_list} if vdom_list else {}))
        if res:
            return True
        return False
    except Exception as err:
        logger.exception('Error with input service name or service name not found. Error is {}'.format(err))
        return False


def create_service_group(config, params):
    try:
        vdom_list, vdom_not_exists = _validate_vdom(config, params, check_multiple_vdom=False)
        mem_lst = _get_list_from_str_or_list(params, 'members')
        body = {
            'name': params.get('name'),
            'member': generate_dict_from_list(mem_lst),
            'comment': params.get('comment')
        }
        body = {k: v for k, v in body.items() if v is not None and v != '' and v != {} and v != []}
        param = {"vdom": vdom_list}
        response = _api_request(config, FIREWALL_SERVICE_GRP_API, parameters=param, body=body, method='POST',
                                header={'accept': 'application/json'})
        return response
    except Exception as Err:
        raise ConnectorError(str(Err))


def get_service_groups(config, params, param=None, Flag=True):
    try:
        if Flag:
            vdom_list, vdom_not_exists = _validate_vdom(config, params, check_multiple_vdom=False)
            param = {"vdom": vdom_list}
        if params.get('name'):
            url = FIREWALL_SERVICE_GRP_API + '/{group_name}'.format(group_name=params.get('name').replace('/', '%2f'))
        else:
            url = FIREWALL_SERVICE_GRP_API
        response = _api_request(config, url , parameters=param, method='GET',
                                header={'accept': 'application/json'})
        return response
    except Exception as Err:
        raise ConnectorError(str(Err))


def update_service_group(config, params):
    try:
        vdom_list, vdom_not_exists = _validate_vdom(config, params, check_multiple_vdom=False)
        param = {"vdom": vdom_list}
        fnl_members_list = []
        curr_members_list = get_service_groups(config, params, param, True).get('results', [])
        if len(curr_members_list) != 1:
            raise ConnectorError('Input service group name not found')

        members_list = get_final_lst(params, curr_members_list, 'member', 'add_member', 'remove_member')
        if not members_list:
            members_list = ['NONE']
        body = {
            'name': params.get('name'),
            'member': generate_dict_from_list(members_list),
            'comment': params.get('comment')
        }
        if params.get('new_name'):
            body.update({'name': params.get('new_name')})
        body = {k: v for k, v in body.items() if v is not None and v != '' and v != {} and v != []}
        url = FIREWALL_SERVICE_GRP_API + '/{group_name}'.format(group_name=params.get('name').replace('/', '%2f'))
        response = _api_request(config, url, parameters=param, body=body, method='PUT',
                                header={'accept': 'application/json'})
        return response
    except Exception as Err:
        raise ConnectorError(str(Err))


def delete_service_group(config, params):
    try:
        vdom_list, vdom_not_exists = _validate_vdom(config, params, check_multiple_vdom=False)
        param = {"vdom": vdom_list}
        url = FIREWALL_SERVICE_GRP_API + '/{group_name}'.format(group_name=params.get('name').replace('/', '%2f'))
        response = _api_request(config, url, parameters=param, method='DELETE', header={'accept': 'application/json'})
        return response
    except Exception as Err:
        raise ConnectorError(str(Err))