#!/usr/bin/env python2
import mechanize
import socket
from urlparse import urlparse
from re import search, sub
import cookielib
import requests
import os
from urllib import urlencode
from plugins.DNSDumpsterAPI import DNSDumpsterAPI
params = []
# Browser
br = mechanize.Browser()

# Just some colors and shit
white = '\033[1;97m'
green = '\033[1;32m'
red = '\033[1;31m'
yellow = '\033[1;33m'
end = '\033[1;m'
info = '\033[1;33m[!]\033[1;m'
que =  '\033[1;34m[?]\033[1;m'
bad = '\033[1;31m[-]\033[1;m'
good = '\033[1;32m[+]\033[1;m'
run = '\033[1;97m[~]\033[1;m'

# Cookie Jar
cj = cookielib.LWPCookieJar()
br.set_cookiejar(cj)

# Browser options
br.set_handle_equiv(True)
br.set_handle_redirect(True)
br.set_handle_referer(True)
br.set_handle_robots(False)

# Follows refresh 0 but not hangs on refresh > 0
br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)
br.addheaders = [
    ('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')]


print '''\033[1;31m
   _________ __          __ __
  /   _____//  |________|__|  | __ ___________
  \_____  \\\\   __\_  __ \  |  |/ // __ \_  __ \\
  /        \|  |  |  | \/  |    <\  ___/|  | \/
 /_______  /|__|  |__|  |__|__|_ \\\\___  >__|
         \/                     \/    \/\033[1;m'''
target = raw_input('\033[1;34m[?]\033[1;m Enter the target: ')
if 'http' in target:
    parsed_uri = urlparse(target)
    domain = '{uri.netloc}'.format(uri=parsed_uri)
else:
    domain = target
    try:
        br.open('http://' + target)
        target = 'http://' + target
    except:
        target = 'https://' + target

def sqli(url):
    print '%s Using SQLMap api to check for SQL injection vulnerabilities. Don\'t worry we are using an online service and it doesn\'t depend on your internet connection. This scan will take 2-3 minutes.' % run
    br.open('https://suip.biz/?act=sqlmap')
    br.select_form(nr=0)
    br.form['url'] = url
    req = br.submit()
    result = req.read()
    match = search(r"---(?s).*---", result)
    if match:
        print '%s One or more parameters are vulnerable to SQL injection' % good
        option = raw_input(
            '%s Would you like to see the whole report? [Y/n] ' % que).lower()
        if option == 'n':
            pass
        else:
            print '\033[1;31m-\033[1;m' * 40
            print match.group().split('---')[1][:-3]
            print '\033[1;31m-\033[1;m' * 40
    else:
        print '%s None of parameters is vulnerable to SQL injection' % bad


def cms(domain):
    try:
        result = br.open('https://whatcms.org/?s=' + domain).read()
        detect = search(r'">[^<]*</a><a href="/New-Detection', result)
        WordPress = False
        try:
            r = br.open(target + '/robots.txt').read()
            if "wp-admin" in str(r):
                WordPress = True
        except:
            pass
        if detect:
            print '%s CMS Detected : %s' % (info, detect.group().split('">')[1][:-27])
            detect = detect.group().split('">')[1][:-27]
            if 'WordPress' in detect:
                option = raw_input(
                    '%s Would you like to use WPScan? [Y/n] ' % que).lower()
                if option == 'n':
                    pass
                else:
                    os.system('wpscan --random-agent --url %s' % domain)
        elif WordPress:
            print '%s CMS Detected : WordPress' % info
            option = raw_input(
                '%s Would you like to use WPScan? [Y/n] ' % que).lower()
            if option == 'n':
                pass
            else:
                os.system('wpscan --random-agent --url %s' % domain)
        else:
            print '%s %s doesn\'t seem to use a CMS' % (info, domain)
    except:
        pass

def honeypot(ip_addr):
    honey = 'https://api.shodan.io/labs/honeyscore/%s?key=C23OXE0bVMrul2YeqcL7zxb6jZ4pj2by' % ip_addr
    try:
        phoney = br.open(honey).read()
        if '0.0' in phoney:
            print '%s Honeypot Probabilty: 0%' % good
        elif '0.1' in phoney:
            print '%s Honeypot Probabilty: 10%' % good
        elif '0.2' in phoney:
            print '%s Honeypot Probabilty: 20%' % good
        elif '0.3' in phoney:
            print '%s Honeypot Probabilty: 30%' % good
        elif '0.4' in phoney:
            print '%s Honeypot Probabilty: 40%' % good
        elif '0.5' in phoney:
            print '%s Honeypot Probabilty: 50%' % bad
        elif '0.6' in phoney:
            print '%s Honeypot Probabilty: 60%' % bad
        elif '0.7' in phoney:
            print '%s Honeypot Probabilty: 70%' % bad
        elif '0.8' in phoney:
            print '%s Honeypot Probabilty: 80%' % bad
        elif '0.9' in phoney:
            print '%s Honeypot Probabilty: 90%' % bad
        elif '1.0' in phoney:
            print '%s Honeypot Probabilty: 100%' % bad
    except:
        print '%s Honeypot prediction failed' % bad

def nmap(ip_addr):
    port = 'http://api.hackertarget.com/nmap/?q=' + ip_addr
    result = br.open(port).read()
    result = sub(r'Starting[^<]*\)\.', '', result)
    result = sub(r'Service[^<]*seconds', '', result)
    result = os.linesep.join([s for s in result.splitlines() if s])
    print result

def bypass(domain):
    post = urlencode({'cfS': domain})
    result = br.open(
        'http://www.crimeflare.info/cgi-bin/cfsearch.cgi ', post).read()

    match = search(r' \b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', result)
    if match:
        bypass.ip_addr = match.group().split(' ')[1][:-1]
        print '%s Real IP Address : %s' % (good, bypass.ip_addr)

def dnsdump(domain):
    res = DNSDumpsterAPI(False).search(domain)
    print '\n%s DNS Records' % good
    for entry in res['dns_records']['dns']:
        print '{domain} ({ip}) {as} {provider} {country}'.format(**entry)
    for entry in res['dns_records']['mx']:
        print '\n%s MX Records' % good
        print '{domain} ({ip}) {as} {provider} {country}'.format(**entry)
    print '\n\033[1;32m[+]\033[1;m Host Records (A)'
    for entry in res['dns_records']['host']:
        if entry['reverse_dns']:
            print '{domain} ({reverse_dns}) ({ip}) {as} {provider} {country}'.format(**entry)
        else:
            print '{domain} ({ip}) {as} {provider} {country}'.format(**entry)
    print '\n%s TXT Records' % good
    for entry in res['dns_records']['txt']:
        print entry
    print '\n%s DNS Map: https://dnsdumpster.com/static/map/%s.png\n' % (good, domain.strip('www.'))


def fingerprint(ip_addr):
    try:
        result = br.open('https://www.censys.io/ipv4/%s/raw' % ip_addr).read()
        match = search(r'&#34;os_description&#34;: &#34;[^<]*&#34;', result)
        if match:
            print '%s Operating System : %s' % (good, match.group().split('n&#34;: &#34;')[1][:-5])
    except:
        pass


ip_addr = socket.gethostbyname(domain)
print '%s IP Address : %s' % (info, ip_addr)
try:
    r = requests.get(target)
    header = r.headers['Server']
    if 'cloudflare' in header:
        print '%s Cloudflare detected' % bad
        bypass(domain)
        try:
            ip_addr = bypass.ip_addr
        except:
            pass
    else:
        print '%s Server: %s' % (info, header)
    try:
        print '%s Powered By: %s' % (info, r.headers['X-Powered-By'])
    except:
        pass
    try:
        r.headers['X-Frame-Options']
    except:
        print '%s Clickjacking protection is not in place.' % good
except:
    pass
fingerprint(ip_addr)
cms(domain)
honeypot(ip_addr)
try:
    r = br.open(target + '/robots.txt').read()
    print '\033[1;31m-\033[1;m' * 40
    print '%s Robots.txt retrieved\n' % good, r
except:
    pass
print '\033[1;31m-\033[1;m' * 40
nmap(ip_addr)
print '\033[1;31m-\033[1;m' * 40
dnsdump(domain)
os.system('cd plugins && python theHarvester.py -d %s -b all' % domain)
try:
    br.open(target)
    print '%s Crawling the target for fuzzable URLs' % run
    for link in br.links():
        if 'http' in link.url or '=' not in link.url:
            pass
        else:
            url = target + '/' + link.url
            params.append(url)
    if len(params) == 0:
        print '%s No fuzzable URLs found' % bad
        quit()
    print '%s Found %i fuzzable URLs' % (good, len(params))
    for url in params:
        print url
        sqli(url)
        url = url.replace('=', '<svg/onload=alert()>')
        r = br.open(url).read()
        if '<svg/onload=alert()>' in r:
            print '%s One or more parameters are vulnerable to XSS' % good
        break
    print '%s These are the URLs having parameters:' % good
    for url in params:
        print url
except:
    pass
