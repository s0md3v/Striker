#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import random
import socket
import argparse
import requests.exceptions
import concurrent.futures

from urllib.parse import urlparse

import core.config
from core.requester import requester
from core.utils import loader, updateVar, var
from core.colors import red, white, end, green, info, good, bad, run, red_line

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
source_1 = findsubdomains(sys.argv[1])
try:
	source_2 = security_trails(sys.argv[1])
except AttributeError:
	source_2 = []
raw_subdomains = list(set(source_1 + source_2))
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
print ('%s Deploying Zoom for subdomain takeovers' % run)
print ('%s Deploying Photon for component assessment' % run)
print ('%s Deploying Alpha for software fingerprinting' % run)
print ('%s Deploying Zetanize for identifying entry points' % run)
print ('%s ETA: %i seconds' % (info, 10 * 2 * len(dataset)))

for subdomain in dataset:
	url = dataset[subdomain]['schema'] + '://' + subdomain
	takeover = False
	for each in var('sub_takeover'):
		for i in each['cname']:
			if i in url:
				try:
					response = requester(url)
					for i in each['fingerprint']:
						if i in response.text:
							takeover = True
							break
				except requests.exceptions.ConnectionError:
					if each['nxdomain']:
						takeover = True
				break
			break
	dataset[subdomain]['cms'] = whatcms(subdomain)
	crawled = photon(url)
	dataset[subdomain]['forms'] = crawled[0]
	dataset[subdomain]['all_urls'] = list(crawled[1])
	dataset[subdomain]['technologies'] = list(crawled[2])
	dataset[subdomain]['outdated_libs'] = crawled[3]

print (json.dumps(dataset, indent=4))
