# SPDX-License-Identifier: Apache-2.0
"""Validate registered Windows endpoint metadata and literal JEA command batches."""

import hashlib
import ipaddress
import json
import math
import re

MAX_JSON = 1024 * 1024


def fields(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= value.keys() or set(value) - set(required) - set(optional):
        raise ValueError('Invalid Windows record fields.')


def text(value, maximum, minimum=1):
    if (not isinstance(value, str) or not minimum <= len(value) <= maximum
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError('Invalid Windows text field.')
    return value


def identity(value, size=32):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{' + str(size) + '}', value):
        raise ValueError('Invalid Windows record identity.')
    return value


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('Invalid Windows integer field.')
    return value


def host(value):
    text(value, 253)
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if (not value.isascii() or not all(re.fullmatch('[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                                          for label in value.split('.'))):
            raise ValueError('Use a Windows host name or IP address.') from None
        return value.lower()


def commands(value):
    if not isinstance(value, list) or not 1 <= len(value) <= 16:
        raise ValueError('Select one to sixteen registered JEA commands.')
    seen = set()
    for item in value:
        fields(item, {'name', 'parameters'})
        name = text(item['name'], 96)
        if not re.fullmatch('[A-Za-z][A-Za-z0-9]{0,46}-[A-Za-z][A-Za-z0-9]{0,46}', name) or name.lower() in seen:
            raise ValueError('Invalid or duplicate JEA command name.')
        seen.add(name.lower())
        params = item['parameters']
        if (not isinstance(params, list) or len(params) > 16
                or any(not isinstance(key, str) or not re.fullmatch('[A-Za-z][A-Za-z0-9]{0,63}', key) for key in params)
                or len({key.lower() for key in params}) != len(params)):
            raise ValueError('Invalid JEA parameter names.')
    if {'name': 'Get-FICCEndpointIdentity', 'parameters': []} not in value:
        raise ValueError('The fixed Windows identity command is required.')
    return value


def literal(value, depth=0, budget=None):
    if budget is None:
        budget = [0]
    budget[0] += 1
    if depth > 16 or budget[0] > 8192:
        raise ValueError('Windows command data exceeds its bound.')
    if value is None or type(value) is bool:
        return
    if type(value) in {int, float}:
        if (type(value) is float and not math.isfinite(value)) or abs(value) > 2**53 - 1:
            raise ValueError('Invalid Windows command number.')
    elif isinstance(value, str):
        if len(value.encode('utf-8')) > 262144 or '\0' in value:
            raise ValueError('Windows command text exceeds its bound.')
    elif isinstance(value, list):
        if len(value) > 4096:
            raise ValueError('Windows command list exceeds its bound.')
        for item in value:
            literal(item, depth + 1, budget)
    elif isinstance(value, dict):
        if len(value) > 128:
            raise ValueError('Windows command object exceeds its bound.')
        for key, item in value.items():
            text(key, 128)
            if key in {'__proto__', 'prototype', 'constructor'}:
                raise ValueError('Invalid Windows command object key.')
            literal(item, depth + 1, budget)
    else:
        raise ValueError('Windows commands require literal JSON data.')


def encode(value):
    literal(value)
    data = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')
    if len(data) > MAX_JSON:
        raise ValueError('Windows message exceeds its byte bound.')
    return data


def decode(data):
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_JSON:
        raise ValueError('Windows message exceeds its byte bound.')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('Duplicate Windows JSON key.')
            value[key] = item
        return value
    value = json.loads(data.decode('utf-8'), object_pairs_hook=unique)
    literal(value)
    return value


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def batch(value, allowed):
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        raise ValueError('Select one to sixty-four JEA commands.')
    permitted = {item['name']: set(item['parameters']) for item in commands(allowed)}
    for item in value:
        fields(item, {'command', 'parameters'})
        text(item['command'], 96)
        if (item['command'] not in permitted or not isinstance(item['parameters'], dict)
                or not set(item['parameters']) <= permitted[item['command']]):
            raise ValueError('The JEA command or parameter is not registered.')
    encode(value)
    return value
