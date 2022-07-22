import re
import sys
from core.requester import requester

def findsubdomains(host):
    response = requester('https://viewdns.info/dnsrecord/?domain=' + host).text
    matches = re.finditer(r'(?s)<tr>(/n)<td>(.*?)</td>', response)
    return [match.group(1).lstrip('\n').rstrip(' ').lstrip(' ') for match in matches]
