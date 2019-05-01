import re
import sys
from core.requester import requester

def findsubdomains(host):
    response = requester('https://findsubdomains.com/subdomains-of/' +
                   host).text
    matches = re.finditer(r'(?s)<div class="domains js-domain-name">(.*?)</div>', response)
    return [match.group(1).lstrip('\n').rstrip(' ').lstrip(' ') for match in matches]
