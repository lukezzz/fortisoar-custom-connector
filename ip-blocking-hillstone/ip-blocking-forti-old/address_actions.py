""" Copyright start
  Copyright (C) 2008 - 2024 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import get_logger, ConnectorError

from .constants import *
from .utils import *
from .utils import _api_request, _validate_vdom

logger = get_logger('fortigate-firewall')


def generate_body_param(config, params):
    try:
        data = {'name': params.get('name'),
                'comment': params.get('comment'),
                'allow-routing': params.get('allow-routing').lower() if params.get('allow-routing') else None
                }
        if params.get('type') == 'Subnet':
            data.update({'subnet': params.get('subnet') + '/32'})
        elif params.get('type') == 'IP Range':
            data.update({'type': 'iprange', 'start-ip': params.get('start_ip'), 'end-ip':params.get('end_ip')})
        elif params.get('type') == 'FQDN':
            data.update({'fqdn': params.get('fqdn'), 'type': 'fqdn'})
        elif params.get('type') == 'Geography':
            for item in country_list:
                if item.get('name') == params.get('country'):
                    data.update({'type': 'geography', 'country': item.get('id')})
                    return data
        elif params.get('type') == 'Device (MAC Address)':
            if params.get('scope') == 'Single Address':
                data.update({'start-mac': params.get('mac_addrs'), 'end-mac': params.get('mac_addrs'),
                             'type': 'mac', 'macaddr': [{"macaddr": params.get('mac_addrs')}]})
            else:
                data.update({'start-mac': params.get('start_mac'), 'end-mac': params.get('end_mac'),
                             'type': 'mac', 'macaddr': [{"macaddr": '{}-{}'.format(params.get('start_mac'),
                                                                                   params.get('end_mac'))}]})
        body_param = {k: v for k, v in data.items() if v is not None and v != '' and v != {} and v != []}
        return body_param
    except Exception as Err:
        raise ConnectorError(str(Err))


def generate_ipv6_body_param(config, params):
    try:
        data = {'name': params.get('name'),
                'comment': params.get('comment')
                }
        if params.get('type') == 'IPv6 Subnet':
            data.update({'ip6': params.get('subnet')})
        elif params.get('type') == 'IPv6 Range':
            data.update({'type': 'iprange', 'start-ip': params.get('start_ip'), 'end-ip': params.get('end_ip')})
        elif params.get('type') == 'IPv6 FQDN':
            data.update({'fqdn': params.get('fqdn'), 'type': 'fqdn'})
        elif params.get('type') == 'IPv6 Geography':
            for item in country_list:
                if item.get('name') == params.get('country'):
                    data.update({'type': 'geography', 'country': item.get('id')})
                    return data
        elif params.get('type') == 'IPv6 Fabric Connector Address':
            data.update({'type': 'dynamic', 'sdn': params.get('sdn_connector')})
        elif params.get('type') == 'IPv6 Template':
            data.update({'type': 'template', 'template': {'q_origin_key': params.get('ipv6_address_template')}})
            if params.get('host_type') == 'Specific':
                data.update({'host-type': 'specific', 'host': params.get('host')})
        elif params.get('type') == 'Device (MAC Address)':
            if params.get('scope') == 'Single Address':
                data.update({'start-mac': params.get('mac_addrs'), 'end-mac': params.get('mac_addrs'),
                             'type': 'mac', 'macaddr': [{"macaddr": params.get('mac_addrs')}]})
            else:
                data.update({'start-mac': params.get('start_mac'), 'end-mac': params.get('end_mac'),
                             'type': 'mac', 'macaddr': [{"macaddr": '{}-{}'.format(params.get('start_mac'),
                                                                                   params.get('end_mac'))}]})
        body_param = {k: v for k, v in data.items() if v is not None and v != '' and v != {} and v != []}
        return body_param
    except Exception as Err:
        raise ConnectorError(str(Err))


def create_address(config, params):
    try:
        vdom_list, vdom_not_exists = _validate_vdom(config, params, check_multiple_vdom=False)
        app_param = {'vdom': vdom_list} if vdom_list else {}
        if params.get('address_category') == 'IPv4 Address':
            data = generate_body_param(config, params)
            return _api_request(config, ADD_ADDRESS, parameters=app_param, body=data, method='POST')
        else:
            data = generate_ipv6_body_param(config, params)
            return _api_request(config, ADD_ADDRESS_IPv6, parameters=app_param, body=data, method='POST')
    except Exception as Err:
        raise ConnectorError(str(Err))


def get_addresses(config, params):
    try:
        vdom_list, vdom_not_exists = _validate_vdom(config, params, check_multiple_vdom=False)
        app_param = {'vdom': vdom_list} if vdom_list else {}
        if params.get('address_category') == 'IPv6 Address':
            url = ADD_ADDRESS_IPv6
        else:
            url = ADD_ADDRESS
        if params.get('name'):
            return _api_request(config, url + str(params.get('name')).replace('/', '%2f'), parameters=app_param)
        else:
            return _api_request(config, url, parameters=app_param)
    except Exception as Err:
        raise ConnectorError(str(Err))


def update_address(config, params):
    try:
        vdom_list, vdom_not_exists = _validate_vdom(config, params, check_multiple_vdom=False)
        app_param = {'vdom': vdom_list} if vdom_list else {}
        if params.get('address_category') == 'IPv4 Address':
            data = generate_body_param(config, params)
            url = ADD_ADDRESS + str(params.get('name')).replace('/', '%2f')
        else:
            data = generate_ipv6_body_param(config, params)
            url = ADD_ADDRESS_IPv6 + str(params.get('name')).replace('/', '%2f')
        if params.get('new_name'):
            data.update({'name': params.get('new_name')})
        return _api_request(config, url, parameters=app_param, body=data, method='PUT')
    except Exception as Err:
        raise ConnectorError(str(Err))


def delete_address(config, params):
    try:
        vdom_list, vdom_not_exists = _validate_vdom(config, params, check_multiple_vdom=False)
        app_param = {'vdom': vdom_list} if vdom_list else {}
        if params.get('address_category') == 'IPv4 Address':
            url = ADD_ADDRESS + params.get('name').replace('/', '%2f')
        else:
            url = ADD_ADDRESS_IPv6 + params.get('name').replace('/', '%2f')
        return _api_request(config, url, parameters=app_param, method='Delete')
    except Exception as Err:
        raise ConnectorError(str(Err))
