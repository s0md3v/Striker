import re
import json

from core.requester import requester

def security_trails(domain):
	response = requester('https://securitytrails.com/list/apex_domain/' + domain).text
	prefixes = json.loads(re.search(r'(?m)"subdomains":(\[.*?\])', response).group(1))
	return [prefix + '.' + domain for prefix in prefixes]
