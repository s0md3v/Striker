import re
import glob
import json
from urllib.parse import urlparse

import core.config


def loader():
    path = var('path')
    for each in glob.glob(path + '/db/*'):
        name = re.search(r'/([^/]*?)\.\w+$', each).group(1)
        if each.endswith('.json'):
            updateVar(name, json.loads(reader(each, mode='joined')))
        else:
            updateVar(name, reader(each))


def make_list(data):
    if 'str' in str(type(data)):
        return [data]
    else:
        return data


def var(name):
    return core.config.globalVars[name]


def updateVar(name, value, mode=None):
    if mode:
        if mode == 'append':
            core.config.globalVars[name].append(value)
        elif mode == 'add':
            core.config.globalVars[name].add(value)
        elif mode == 'extend':
            core.config.globalVars[name].extend(value)
    else:
        core.config.globalVars[name] = value


def reader(path, mode=None):
    with open(path, 'r') as f:
        result = [line.rstrip(
                    '\n').encode('utf-8').decode('utf-8') for line in f]
        if mode == 'joined':
            result = '\n'.join(result)
        return result


def getUrl(url, GET):
    if GET:
        return url.split('?')[0]
    else:
        return url


def getParams(url, data, GET):
    params = {}
    if GET:
        if '=' in url:
            data = url.split('?')[1]
            if data[:1] == '?':
                data = data[1:]
        else:
            data = ''
    parts = data.split('&')
    for part in parts:
        each = part.split('=')
        try:
            params[each[0]] = each[1]
        except IndexError:
            params = None
    return params


def deJSON(data):
    return data.replace('\\\\', '\\')


def writer(obj, path):
    kind = str(type(obj)).split('\'')[0]
    if kind == 'list' or kind == 'tuple':
        obj = '\n'.join(obj)
    elif kind == 'dict':
        obj = json.dumps(obj, indent=4)
    savefile = open(path, 'w+')
    savefile.write(str(obj.encode('utf-8')))
    savefile.close()


def script_extractor(response):
    """Extract js files from the response body"""
    scripts = []
    matches = re.findall(r'<(?:script|SCRIPT).*?(?:src|SRC)=([^\s>]+)', response)
    for match in matches:
        match = match.replace('\'', '').replace('"', '').replace('`', '')
        scripts.append(match)
    return scripts

def js_extractor(response):
    """Extract js code from the response body"""
    scripts = []
    matches = re.finditer(r'(?m)<(?:script|SCRIPT)[^>]*>(.*?)</(?:script|SCRIPT)>', response)
    for match in matches:
        scripts.append(match.group(1))
    return scripts


def handle_anchor(parent_url, url):
    scheme = urlparse(parent_url).scheme
    if url[:4] == 'http':
        return url
    elif url[:2] == '//':
        return scheme + ':' + url
    elif url.startswith('/'):
        host = urlparse(parent_url).netloc
        parent_url = scheme + '://' + host
        return parent_url + url
    elif parent_url.endswith('/'):
        return parent_url + url
    else:
        return parent_url + '/' + url

def isProtected(parsed):
    protected = False
    parsedForms = list(parsed.values())
    for oneForm in parsedForms:
        inputs = oneForm['inputs']
        for inp in inputs:
            name = inp['name']
            kind = inp['type']
            value = inp['value']
            if re.match(r'^[\w\-_+=/]{14,256}$', value):
                protected = True
    return protected
