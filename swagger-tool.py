#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import copy
import json
import logging
import os
import queue
import sys
import threading
import traceback
from urllib.parse import urlparse

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
    parser.add_argument("--timeout", dest="timeout", help="设置超时时间", type=int, default=10)
    parser.add_argument("--thread", dest="thread", help="线程数量", type=int, default=1)
    parser.add_argument("--proxy", dest="proxies", help="代理地址 eg: http://127.0.0.1:8080", )
    parser.add_argument("--no-request", dest="no_request", help="仅解析接口,不发送请求", action='store_true')

    args = parser.parse_args()
    if args.target:
        global_config['target'] = args.target
    if args.base_url:
        global_config['base_url'] = args.base_url
    if args.timeout:
        global_config['timeout'] = args.timeout
    if args.thread:
        global_config['thread'] = args.thread
    if args.proxies:
        global_config['proxies'] = {"http": args.proxies, "https": args.proxies, }
    if args.skip_not_require_param:
        global_config['skip_not_require_param'] = args.skip_not_require_param
    if args.no_request:
        global_config['no_request'] = args.no_request


# 这里还是有bug
def get_originalRef_vulue(originalRef, deep=1):
    originalRef_info = api_data['definitions'][originalRef]
    object_param = {}
    if deep > 5:
        if originalRef_info['type'] == 'object':
            return {}
        elif originalRef_info['type'] == 'array':
            return []
        else:
            return ''

    for param_key in originalRef_info['properties']:
        # 这里应该增加特殊类型解析
        if param_key in default_value:
            param_value = default_value[param_key]
        elif 'default' in originalRef_info['properties'][param_key]:
            param_value = originalRef_info['properties'][param_key][
                'default']
        elif originalRef_info['properties'][param_key].get('type', '') in default_type_value:
            # 类型的默认值
            param_type = originalRef_info['properties'][param_key]['type']
            param_value = default_type_value[param_type]

            if param_type == 'array' and 'items' in originalRef_info['properties'][param_key]:
                if 'originalRef' in originalRef_info['properties'][param_key]['items']:
                    originalRef2 = originalRef_info['properties'][param_key]['items']['originalRef']
                    param_value = get_originalRef_vulue(originalRef2, deep=deep + 1)
            elif param_type == 'object':
                originalRef2 = originalRef_info['properties'][param_key]['originalRef']
                param_value = get_originalRef_vulue(originalRef2, deep=deep + 1)

        else:
            param_value = 'test'
        object_param[param_key] = param_value
    return object_param


def send_request(path, method):
    url = global_config['base_url'] + path

    query_data = copy.deepcopy(common_params)
    body_data = copy.deepcopy(common_params)
    headers = copy.deepcopy(common_headers)

    object_param = {}  # 如果是list 该是什么样？

    global success_counter
    global warring_counter
    global error_counter

    item = api_data['paths'][path]
    if 'parameters' in item[method]:
        for param in item[method]['parameters']:
            try:
                param_key = param['name']
                param_in = param.get('in',
                                     'query')
                param_required = param['required']
                param_type = param.get('type', 'null')

                if 'schema' in param:
                    if 'originalRef' in param['schema']:
                        originalRef = param['schema']['originalRef']
                        object_param = get_originalRef_vulue(originalRef)

                    elif 'type' in param['schema']:
                        param_type = param['schema']['type']
                        # param_format = param['schema']['format']
                    param_value = object_param

                elif param_key in default_value:
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
                elif param_in == 'header':
                    headers[param_key] = param_value
                elif param_in == 'path':
                    url = url.replace('{' + param_key + '}', str(param_value))
                else:
                    logger.warning('param path error {}'.format(param))

            except Exception as e:
                # print(traceback.format_exc())
                logger.warning('param error2 {} : {}'.format(param, e))
                # exit()

    if 'consumes' in item[method] and 'application/json' in item[method]['consumes']:
        headers['Content-Type'] = 'application/json'

    if global_config['no_request']:
        logger.info(
            '{} {} {}'.format(url, method, item[method].get('summary', '')))
        success_counter += 1
    else:
        try:
            if headers and headers.get('Content-Type', '') == 'application/json':
                body_data = json.dumps(object_param) 
            response = requests.request(method, url=url, params=query_data, data=body_data,
                                        proxies=proxies, verify=False, headers=headers,
                                        timeout=global_config['timeout'])

            logger.info(
                '{} {} {} send success ,response {}'.format(url, method, item[method].get('summary', ''),
                                                            response.status_code))
            success_counter += 1
        except Exception as e:
            # print(traceback.format_exc())
            error_counter += 1
            logger.error('{} {} request error: {}'.format(url, method, e.args))


def run():
    while True:
        try:
            path, method = api_queue.get_nowait()
        except queue.Empty:
            break
        send_request(path, method)


if __name__ == '__main__':
    cmd_init()
    logger.info('config init success.')
    common_params = global_config['common_params']
    common_headers = global_config['common_headers']
    default_value = global_config['default_value']
    default_type_value = global_config['default_type_value']
    proxies = global_config['proxies']

    api_queue = queue.Queue()

    success_counter = 0
    warring_counter = 0
    error_counter = 0

    if global_config['target'].startswith('http'):
        response = requests.get(global_config['target'], headers=common_headers_dict, proxies=proxies,
                                timeout=global_config['timeout'], verify=False)
        api_json = response.text
        if not (
                response.status_code == 200 and 'paths' in response.text and 'info' in response.text):
            logger.error('api-docs check error , exit ...')
            exit(0)

        api_data = json.loads(api_json)
    else:
        api_data = json.loads(open(global_config['target']).read())

    logger.info('load swagger-doc success')

    if global_config['base_url'] == '':
        global_config['base_url'] = api_data['host'] + api_data['basePath']
    if not global_config['base_url'].startswith('http'):
        global_config['base_url'] = 'http://' + global_config['base_url']

    logger.info('base url: ' + global_config['base_url'])
    logger.info('start send requests')

    for path in api_data['paths']:
        if path in global_config['skip_url']:
            continue

        item = api_data['paths'][path]
        method_list = item.keys()
        for method in method_list:
            api_queue.put((path, method))

    # 多线程扫描
    thread_list = []
    for i in range(global_config['thread']):
        thread = threading.Thread(target=run)
        thread.start()
        thread_list.append(thread)
    for thread in thread_list:
        thread.join()

    print('\nTask Completed. success: {}, warring: {}, error: {}, total: {}.'.format(success_counter, warring_counter,
                                                                                     error_counter,
                                                                                     success_counter + warring_counter + error_counter))
