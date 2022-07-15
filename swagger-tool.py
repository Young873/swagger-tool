#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import copy
import json
import logging
import sys
import traceback

import requests

from default_value import *

requests.packages.urllib3.disable_warnings()

global_config = {
    'target': '',

    'base_url': '',
    'skip_not_require_param': True,
    'proxies': None,
    'no_request': False,

    'skip_url': [],

    'common_headers': common_headers_dict,
    'common_params': common_params_dict,
    'default_value': default_value_dict,
    'default_type_value': default_type_value_dict,
}

FORMATTER = logging.Formatter("\r[%(asctime)s] [%(levelname)s] %(message)s", "%H:%M:%S")
LOGGER_HANDLER = logging.StreamHandler(sys.stdout)
LOGGER_HANDLER.setFormatter(FORMATTER)
logger = logging.getLogger()
logger.addHandler(LOGGER_HANDLER)
logger.setLevel(logging.INFO)


def cmd_init():
    usage = "swagger-tool.py [options]\n\tpython3 swagger-tool.py -t http://xxxxx.com/v2/api-docs"
    parser = argparse.ArgumentParser(prog='swagger-tool', usage=usage)

    parser.add_argument("-t", dest="target", help="检测的目标地址 api-doc文件 api-doc地址", required=True)
    parser.add_argument("--base-url", dest="base_url", help="目标根路径,默认使用api-docs解析的地址")
    parser.add_argument("--skip-not-require-param", dest="skip_not_require_param", help="不发送非必要参数", default=False,
                        type=bool)
    parser.add_argument("--proxy", dest="proxies", help="代理地址 eg: http://127.0.0.1:8080", )
    parser.add_argument("--no-request", dest="no_request", help="仅解析接口,不发送请求", action='store_true')

    args = parser.parse_args()
    if args.target:
        global_config['target'] = args.target
    if args.base_url:
        global_config['base_url'] = args.base_url
    if args.proxies:
        global_config['proxies'] = {"http": args.proxies, "https": args.proxies, }
    if args.skip_not_require_param:
        global_config['skip_not_require_param'] = args.skip_not_require_param
    if args.no_request:
        global_config['no_request'] = args.no_request


def param2dict(method):
    originalRef = item[method]['parameters'][0]['schema']['originalRef']
    body_data = {}
    for param_key in api_data['definitions'][originalRef]['properties']:
        if param_key in default_value:
            param_value = default_value[param_key]
        elif api_data['definitions'][originalRef]['properties'][param_key][
            'type'] in default_type_value:
            param_type = api_data['definitions'][originalRef]['properties'][param_key]['type']
            param_value = default_type_value[param_type]
        elif 'default' in api_data['definitions'][originalRef]['properties'][param_key]:
            param_value = api_data['definitions'][originalRef]['properties'][param_key][
                'default']
        else:
            param_value = 'test'
        body_data[param_key] = param_value
    return body_data


if __name__ == '__main__':
    cmd_init()
    logger.info('config init success.')
    common_params = global_config['common_params']
    common_headers = global_config['common_headers']
    default_value = global_config['default_value']
    default_type_value = global_config['default_type_value']
    proxies = global_config['proxies']

    success_counter = 0
    warring_counter = 0
    error_counter = 0

    if global_config['target'].startswith('http'):
        api_data = json.loads(requests.get(global_config['target']).text)
    else:
        api_data = json.loads(open('0607.json').read())

    logger.info('load swagger-doc success')

    base_url = global_config['base_url']
    if base_url == '':
        base_url = api_data['host']
    if not base_url.startswith('http'):
        base_url = 'http://' + base_url
    logger.info('base url: ' + base_url)
    logger.info('start send requests')
    for path in api_data['paths']:
        if path in global_config['skip_url']:
            continue

        item = api_data['paths'][path]  # 这个接口的get post put等方法
        method_list = item.keys()
        for method in method_list:
            url = base_url + path

            query_data = copy.deepcopy(common_params)
            body_data = copy.deepcopy(common_params)
            headers = copy.deepcopy(common_headers)

            if 'parameters' in item[method]:
                for param in item[method]['parameters']:
                    try:
                        param_key = param['name']
                        param_in = param['in']
                        param_required = param['required']
                        param_type = param.get('type', 'null')

                        if param_key in default_value:
                            param_value = default_value[param_key]
                        elif param_type in default_type_value:
                            param_value = default_type_value[param_type]
                        elif 'default' in param:
                            param_value = param['default']
                        else:
                            param_value = 'test'

                        if not param_required and not global_config['skip_not_require_param']:
                            continue

                        if param_in == 'query':
                            query_data[param_key] = param_value
                        elif param_in == 'body':
                            body_data[param_key] = param_value
                        elif param_in == 'path':
                            url = url.replace('{' + param_key + '}', str(param_value))
                        else:
                            logger.warning('param path error {}'.format(param))
                    except:
                        logger.warning('param error2 {}'.format(param))

            if global_config['no_request']:
                logger.info(
                    '{} {} {}'.format(base_url + path, method, item[method].get('summary', '')))
                success_counter += 1
            else:
                try:
                    if method == 'get':
                        response = requests.get(url=url, params=query_data, proxies=proxies, verify=False,
                                                headers=headers)

                        success_counter += 1
                    elif method == 'post':
                        if 'consumes' in item['post'] and 'application/json' in item['post']['consumes']:
                            headers['Content-Type'] = 'application/json'
                            if 'parameters' in item[method] and len(item[method]['parameters']) == 1 and 'schema' in \
                                    item[method]['parameters'][0]:
                                body_data = param2dict(method)

                            response = requests.post(url=base_url + path, params=query_data, data=json.dumps(body_data),
                                                     proxies=proxies, verify=False, headers=headers)
                        else:
                            response = requests.post(url=base_url + path, params=query_data, data=body_data,
                                                     proxies=proxies,
                                                     verify=False, headers=headers)

                        success_counter += 1
                    elif method == 'head':
                        if 'consumes' in item['post'] and 'application/json' in item['post']['consumes']:
                            headers['Content-Type'] = 'application/json'
                            if 'parameters' in item[method] and len(item[method]['parameters']) == 1 and 'schema' in \
                                    item[method]['parameters'][0]:
                                body_data = param2dict(method)

                            response = requests.head(url=base_url + path, params=query_data, data=json.dumps(body_data),
                                                     proxies=proxies, verify=False, headers=headers)
                        else:
                            response = requests.head(url=base_url + path, params=query_data, data=body_data,
                                                     proxies=proxies,
                                                     verify=False, headers=headers)
                        success_counter += 1
                    elif method == 'put':
                        if 'consumes' in item['post'] and 'application/json' in item['post']['consumes']:
                            headers['Content-Type'] = 'application/json'
                            if 'parameters' in item[method] and len(item[method]['parameters']) == 1 and 'schema' in \
                                    item[method]['parameters'][0]:
                                body_data = param2dict(method)

                            response = requests.put(url=base_url + path, params=query_data, data=json.dumps(body_data),
                                                    proxies=proxies, verify=False, headers=headers)
                        else:
                            response = requests.put(url=base_url + path, params=query_data, data=body_data,
                                                    proxies=proxies,
                                                    verify=False, headers=headers)
                        success_counter += 1
                    elif method == 'delete':
                        if 'consumes' in item['post'] and 'application/json' in item['post']['consumes']:
                            headers['Content-Type'] = 'application/json'
                            if 'parameters' in item[method] and len(item[method]['parameters']) == 1 and 'schema' in \
                                    item[method]['parameters'][0]:
                                body_data = param2dict(method)

                            response = requests.delete(url=base_url + path, params=query_data,
                                                       data=json.dumps(body_data),
                                                       proxies=proxies, verify=False, headers=headers)
                        else:
                            response = requests.delete(url=base_url + path, params=query_data, data=body_data,
                                                       proxies=proxies,
                                                       verify=False, headers=headers)
                        success_counter += 1
                    elif method == 'options':
                        if 'consumes' in item['post'] and 'application/json' in item['post']['consumes']:
                            headers['Content-Type'] = 'application/json'
                            if 'parameters' in item[method] and len(item[method]['parameters']) == 1 and 'schema' in \
                                    item[method]['parameters'][0]:
                                body_data = param2dict(method)

                            response = requests.options(url=base_url + path, params=query_data,
                                                        data=json.dumps(body_data),
                                                        proxies=proxies, verify=False, headers=headers)
                        else:
                            response = requests.options(url=base_url + path, params=query_data, data=body_data,
                                                        proxies=proxies,
                                                        verify=False, headers=headers)
                        success_counter += 1
                    elif method == 'patch':
                        if 'consumes' in item['post'] and 'application/json' in item['post']['consumes']:
                            headers['Content-Type'] = 'application/json'
                            if 'parameters' in item[method] and len(item[method]['parameters']) == 1 and 'schema' in \
                                    item[method]['parameters'][0]:
                                body_data = param2dict(method)

                            response = requests.patch(url=base_url + path, params=query_data,
                                                      data=json.dumps(body_data),
                                                      proxies=proxies, verify=False, headers=headers)
                        else:
                            response = requests.patch(url=base_url + path, params=query_data, data=body_data,
                                                      proxies=proxies,
                                                      verify=False, headers=headers)
                        success_counter += 1
                    else:
                        response = requests.post(url=base_url + path, params=query_data, data=body_data,
                                                 proxies=proxies,
                                                 verify=False, headers=headers)
                        warring_counter += 1
                        logger.warning('{} unimplement,using post method'.format(method))

                    logger.info(
                        '{} {} {} send success ,response {}'.format(base_url + path, method,
                                                                    item[method].get('summary', ''),
                                                                    response.status_code))

                except:
                    # print(traceback.format_exc())
                    error_counter += 1
                    logger.error('{} {} request error'.format(base_url + path, method))

    print('\nTask Completed. success: {}, warring: {}, error: {}, total: {}.'.format(success_counter, warring_counter,
                                                                                     error_counter,
                                                                                     success_counter + warring_counter + error_counter))
