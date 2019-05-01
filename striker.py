import os
import sys
import json
import random
import socket
import argparse
import concurrent.futures

from urllib.parse import urlparse

import core.config
from core.utils import loader, updateVar, var
from core.colors import red, white, end, green, dgreen, info, good, bad, run, red_line

print ('''%s
.                   
  ` .        .             .        . `
      ` .     .  %sStriker%s  .     . `
          ` .` .         . `. `
              ` . ` . ` . `
                  ` . `
%s''' % (red, white, red, end))
print ('%s Running component level check' % run)
print ('%s Starting engine' % run)
updateVar('path', sys.path[0])
updateVar('checkedScripts', set())
loader()
from core.photon import photon

from modules.whatcms import whatcms
from modules.portscanner import portscanner
from modules.findsubdomains import findsubdomains
from modules.security_trails import security_trails

print ('%s Turning on radar' % run)
dataset = {}
raw_subdomains = list(set(findsubdomains(sys.argv[1]) + security_trails(sys.argv[1])))
raw_subdomains.append(sys.argv[1])
print ('%s %i targets were caught on radar.' % (info, len(raw_subdomains)))
unique_ips = {}
for raw_subdomain in raw_subdomains:
	try:
		ip = socket.gethostbyname(raw_subdomain)
		dataset[raw_subdomain] = {}
		dataset[raw_subdomain]['ip'] = ip
		if ip not in unique_ips:
			open_ports = portscanner([(ip, port) for port in var('ports')])
			dataset[raw_subdomain]['ports'] = open_ports
			unique_ips[ip] = open_ports
			if 443 in open_ports:
				dataset[raw_subdomain]['schema'] = 'https'
			else:
				dataset[raw_subdomain]['schema'] = 'http'
		else:
			open_ports = unique_ips[ip]
			dataset[raw_subdomain]['ports'] = open_ports
			if 443 in open_ports:
				dataset[raw_subdomain]['schema'] = 'https'
			else:
				dataset[raw_subdomain]['schema'] = 'http'
		print ('%s[✈️]%s %s' % (green, end, raw_subdomain))
	except (socket.gaierror, UnicodeError):
		pass

# print ('%s Deploying wavelet analyzing module to detect hidden targets.' % run)
# print ('Wavelets analyzed [1/1]')
print ('%s Deploying Photon for component assessment' % run)
print ('%s Deploying Alpha for software fingerprinting' % run)
print ('%s Deploying Zetanize for identifying entry points' % run)
print ('%s ETA: %i seconds' % (info, 10 * 2 * len(dataset)))

for subdomain in dataset:
	dataset[subdomain]['cms'] = whatcms(subdomain)
	crawled = photon(dataset[subdomain]['schema'] + '://' + subdomain)
	dataset[subdomain]['forms'] = crawled[0]
	dataset[subdomain]['all_urls'] = list(crawled[1])
	dataset[subdomain]['technologies'] = list(crawled[2])
	dataset[subdomain]['outdated_libs'] = crawled[3]

print (json.dumps(dataset, indent=4))

# print ('%s Deploying Bolt for CSRF detection' % run)
# print ('%s Deploying XSStrike for XSS detection' % run)
# print ('%s Deploying Zoom to scan for camouflaged components' % run)
# print ('%s Deploying Zeta to find open redirect vulnerabilities' % run)
# print ('%s Deploying Hawk to find file inclusion vulnerabilities' % run)

# for subdomain in dataset:
# 	print ('%s Attacking [%s]' % (info, subdomain))
# 	for form in dataset[subdomain]['forms']:
# 		for each in form.values():
#             url = each['action']
#             if url:
#                 if url.startswith(main_url):
#                     pass
#                 elif url.startswith('//') and url[2:].startswith(host):
#                     url = scheme + '://' + url[2:]
#                 elif url.startswith('/'):
#                     url = scheme + '://' + host + url
#                 elif re.match(r'\w', url[0]):
#                     url = scheme + '://' + host + '/' + url
#                 if url not in core.config.globalVariables['checkedForms']:
#                     core.config.globalVariables['checkedForms'][url] = []
#                 method = each['method']
#                 GET = True if method == 'get' else False
#                 inputs = each['inputs']
#                 paramData = {}
#                 for one in inputs:
#                     paramData[one['name']] = one['value']
#                     for paramName in paramData.keys():
#                             core.config.globalVariables['checkedForms'][url].append(paramName)
#                             paramsCopy = copy.deepcopy(paramData)

