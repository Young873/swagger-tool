#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 参数对应的默认的参数值
default_value_dict = {
    'pageSize': 10,
    'pageNo': 1,
}

# 如果没有默认参数值，将根据参数类型设置以下默认值
default_type_value_dict = {
    'integer': 1,
    'int32': 1,
    'int64': 1,
    'string': 'test',
    'number': 10,
    'boolean': False,
    'object': '',
    'array': [],

    'null': 'testnull'
}

# 公共请求头
common_headers_dict = {
    # 'token': 'xxxx'
}

# 公共参数
common_params_dict = {}
