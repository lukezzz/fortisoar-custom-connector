""" Copyright start
  Copyright (C) 2008 - 2024 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import get_logger, ConnectorError

from .constants import *
from .utils import *
from .utils import _api_request, _validate_vdom, _get_list_from_str_or_list

logger = get_logger('fortigate-firewall')


def get_members_list(config, params, vdom_list):
    curr_mem_list = get_address_groups(config, params, vdom_list).get('results', [])
    if len(curr_mem_list) != 1:
        raise ConnectorError('Input Address Group name not found')

    members_list = get_final_lst(params, curr_mem_list, 'member', 'add_member', 'remove_member')
    if params.get('exclude'):
        exclude_mem_list = get_final_lst(params, curr_mem_list, 'exclude-member', 'add_exclude_member',
                                         'remove_exclude_member')
    else:
        exclude_mem_list = []
    return members_list, exclude_mem_list


def create_address_group(config, params):
    try:
        vdom_list, vdom_not_exists = _validate_vdom(config, params, check_multiple_vdom=False)
        querystring = {}
        if vdom_list:
            querystring.update({'vdom': ','.join(vdom_list)})
        ip_list = _get_list_from_str_or_list(params, 'member')
        if params.get('exclude'):
            exclude_ip_list = _get_list_from_str_or_list(params, 'exclude_member')
        else:
            exclude_ip_list = []
        data = {
            'name': params.get('group_name'),
            'type': 'folder' if params.get('type') == 'Folder' else 'default',
            'member': generate_dict_from_list(ip_list),
            'exclude': 'enable' if params.get('exclude') else None,
            'exclude-member': generate_dict_from_list(exclude_ip_list),
            'comment': params.get('comment'),
            'allow-routing': params.get('allow-routing').lower() if params.get('allow-routing') else None
        }
        data = {k: v for k, v in data.items() if v is not None and v != '' and v != {} and v != []}
        if params.get('address_group_category') == 'IPv4 Group':
            response = _api_request(config, ADDRESS_GROUP_ALL_API, parameters=querystring, body=data, method='POST')
        else:
            response = _api_request(config, ADDRESS_GROUP_ALL_API_IPv6, parameters=querystring, body=data, method='POST')
        return response
    except Exception as Err:
        raise ConnectorError(str(Err))


def get_address_groups(config, params, vdom_list=None):
    try:
        if not vdom_list:
            vdom_list, vdom_not_exists = _validate_vdom(config, params, check_multiple_vdom=False)
        querystring= {}
        if vdom_list:
            querystring.update({'vdom': ','.join(vdom_list)})

        if params.get('address_group_category') == 'IPv6 Group':
            url = ADDRESS_GROUP_ALL_API_IPv6
        else:
            url = ADDRESS_GROUP_ALL_API
        if params.get('group_name'):

            response = _api_request(config, '{0}/{1}'.format(url, params.get('group_name')), parameters=querystring)
        else:
            if vdom_list:
                querystring.update({'vdom': ','.join(vdom_list)})
            response = _api_request(config, url, parameters=querystring)
        return response
    except Exception as Err:
        raise ConnectorError(str(Err))


def update_address_group(config, params):
    try:
        vdom_list, vdom_not_exists = _validate_vdom(config, params, check_multiple_vdom=False)
        querystring = {}
        if vdom_list:
            querystring.update({'vdom': ','.join(vdom_list)})
        response_list = []
        for vdom in vdom_list:
            members_list, exclude_mem_list = get_members_list(config, params, [vdom])
            if params.get('address_group_category') == 'IPv4 Group':
                url = ADDRESS_GROUP_API
            else:
                url = ADDRESS_GROUP_API_IPv6
            data = {
                'name': params.get('group_name'),
                'comment': params.get('comment'),
                'allow-routing': params.get('allow-routing').lower() if params.get('allow-routing') else None
            }
            data = {k: v for k, v in data.items() if v is not None and v != '' and v != {} and v != []}
            if type(params.get('exclude')) is bool:
                if params.get('exclude'):
                    data['exclude'] = 'enable'
                    data['exclude-member'] = generate_dict_from_list(exclude_mem_list)
            if params.get('add_member') or params.get('remove_member'):
                data['member'] = generate_dict_from_list(members_list)
            if params.get('new_group_name'):
                data.update({'name': params.get('new_group_name')})
            response = _api_request(config, url.format(ip_group_name=params.get('group_name').replace('/', '%2f')),
                                    parameters={'vdom': vdom}, body=data, method='PUT')
            response_list.append(response)
        return response_list
    except Exception as Err:
        raise ConnectorError(str(Err))


def delete_address_group(config, params):
    try:
        vdom_list, vdom_not_exists = _validate_vdom(config, params, check_multiple_vdom=False)
        querystring ={}
        if params.get('address_group_category') == 'IPv4 Group':
            url = ADDRESS_GROUP_API
        else:
            url = ADDRESS_GROUP_API_IPv6
        if vdom_list:
            querystring.update({'vdom': ','.join(vdom_list)})
        response = _api_request(config, url.format(ip_group_name=params.get('group_name').replace('/', '%2f')),
                                parameters=querystring, method='DELETE')
        return response
    except Exception as Err:
        raise ConnectorError(str(Err))
