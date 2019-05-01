import re

from core.requester import requester

def whatcms(domain):
    response = requester('https://whatcms.org/?gpreq=json&jsoncallback=jQuery1124008091494457806547_1554361369057&s=%s&na=&nb=1cg805dlm7d7e5eickf67rzxrn12mju6bnch3a99hrt88v7n8rhf0lovwr8d0zm1&verified=&_=1554361369059' % domain).text
    match = re.search(r'uses<\\/div>[^>]+>(.*?)<\\/a>', response)
    if match:
    	return match.group(1)
    else:
    	return None