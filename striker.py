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
import whois
import json
import subprocess as sp

import argparse
import sys

#get theHarvesterLib.py module
sys.path.insert(0,str(os.getcwd())+"/plugins")
#import theHarvesterLib
import theHarvesterLib


class writer:
    inMemoryLog=b''
    target=''
    logFile=''
    def cmdline(self):
        parser=argparse.ArgumentParser()
        parser.add_argument("-t","--target")
        parser.add_argument("-l","--logfile")
        options=parser.parse_args()

        if options.target:
            self.target=options.target
            print '\033[1;34m[!]\033[1;m Target Provided by Cmd-Args: {}'.format(options.target)
        else:
            self.target = raw_input('\033[1;34m[?]\033[1;m Enter the target: ')

        if options.logfile:
            self.logFile=options.logfile
        else:
            self.logFile=None

        return self.target

    def actualWrite(self):
        if self.logFile != None:
            file=open(self.logFile,"wb")
            file.write(self.inMemoryLog)
            file.close()
    #to reduce unnecessary code, put the print inside of writeLog, do the logging in the same location
    def writeLog(self,string=b'',ignorePrint=False):
        if ignorePrint == False:
            print string
        if self.logFile != None:
            self.inMemoryLog+=string+b"\n"

logger=writer()        

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


string='''\033[1;31m
   _________ __          __ __
  /   _____//  |________|__|  | __ ___________
  \_____  \\\\   __\_  __ \  |  |/ // __ \_  __ \\
  /        \|  |  |  | \/  |    <\  ___/|  | \/
 /_______  /|__|  |__|  |__|__|_ \\\\___  >__|
         \/                     \/    \/\033[1;m'''
logger.writeLog(string.encode()+"\n".encode())
target=logger.cmdline()
logger.writeLog(yellow+b"Target: "+end+target.encode()+"\n".encode(),ignorePrint=True)

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
    string='{} Using SQLMap api to check for SQL injection vulnerabilities. Don\'t worry we are using an online service and it doesn\'t depend on your internet connection. This scan will take 2-3 minutes.'.format(run)
    br.open('https://suip.biz/?act=sqlmap')
    br.select_form(nr=0)
    br.form['url'] = url
    req = br.submit()
    result = req.read()
    match = search(r"---(?s).*---", result)
    if match:
        string='{} One or more parameters are vulnerable to SQL injection'.format(good)
        logger.writeLog(string.encode())
        option = raw_input(
            '%s Would you like to see the whole report? [Y/n] ' % que).lower()
        if option == 'n':
            pass
        else:
            string='\033[1;31m-\033[1;m' * 40
            logger.writeLog(string.encode())
            string=match.group().split('---')[1][:-3]
            logger.writeLog(string.encode())
            string='\033[1;31m-\033[1;m' * 40
            logger.writeLog(string.encode())
    else:
        string='%s None of parameters is vulnerable to SQL injection'.format(bad)
        logger.writeLog(string.encode())


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
            string='{} CMS Detected : {}'.format(info, detect.group().split('">')[1][:-27])
            logger.writeLog(string.encode())
            detect = detect.group().split('">')[1][:-27]
            if 'WordPress' in detect:
                option = raw_input(
                    '%s Would you like to use WPScan? [Y/n] ' % que).lower()
                if option == 'n':
                    pass
                else:
                    data=sp.Popen('wpscan --random-agent --url {}'.format(domain),shell=True,stdout=sp.PIPE)
                    stdout,stderr=data.communicate()
                    logger.writeLog(stdout.encode())

        elif WordPress:
            string='{} CMS Detected : WordPress'.format(info)
            logger.writeLog(string.encode())
            option = raw_input(
                '%s Would you like to use WPScan? [Y/n] ' % que).lower()
            #seriously, you should check for y anything else will be ignored
            if option == 'n':
                pass
            else:
                data=sp.Popen('wpscan --random-agent --url {}'.format(domain),shell=True,stdout=sp.PIPE)
                stdout,stderr=data.communicate()
                logger.writeLog(stdout.encode())

        else:
            string='{} {} doesn\'t seem to use a CMS'.format(info, domain)
            logger.writeLog(string.encode())
    except:
        pass

def honeypot(ip_addr):
    result = {"0.0": 0, "0.1": 10, "0.2": 20, "0.3": 30, "0.4": 40, "0.5": 50, "0.6": 60, "0.7": 70, "0.8": 80, "0.9": 90, "1.0": 10}
    honey = 'https://api.shodan.io/labs/honeyscore/%s?key=C23OXE0bVMrul2YeqcL7zxb6jZ4pj2by' % ip_addr
    try:
        phoney = br.open(honey).read()
        if float(phoney) >= 0.0 and float(phoney) <= 0.4:
            what = good
        else:
            what = bad
        string='{} Honeypot Probabilty: {}%'.format(what, result[phoney])
        logger.writeLog(string.encode())
    except KeyError:
        string='\033[1;31m[-]\033[1;m Honeypot prediction failed'
        logger.writeLog(string.encode())

def whoisIt(url):
    who = ""
    string='{} Trying to gather whois information for {}'.format(run,url)
    logger.writeLog(string.encode())
    try:
        who = str(whois.whois(url)).decode()
    except Exception:
        pass
    test = who.lower()
    if "whoisguard" in test or "protection" in test or "protected" in test:
        string='{} Whois Protection Enabled{}'.format(bad, end)
        logger.writeLog(string.encode())
    else:
        string='{} Whois information found{}'.format(good, end)
        logger.writeLog(string.encode())
        try:
            data = json.loads(who)
            for key in data.keys():
                stringHead="{} :".format(key.replace("_", " ").title())
                logger.writeLog(''.join(stringHead).encode())
                if type(data[key]) == list:
                    string=", ".join(data[key])
                else:
                    string="{}".format(data[key])
                stringTotal=''.join(stringHead)+" "+''.join(string)
                logger.writeLog(stringTotal)
        except ValueError:
            string='{} Unable to build response, visit https://who.is/whois/{} {}'.format(bad, url, end) 
            logger.writeLog(string.encode())
    pass

def nmap(ip_addr):
    port = 'http://api.hackertarget.com/nmap/?q=' + ip_addr
    result = br.open(port).read()
    result = sub(r'Starting[^<]*\)\.', '', result)
    result = sub(r'Service[^<]*seconds', '', result)
    result = os.linesep.join([s for s in result.splitlines() if s])
    logger.writeLog(result.encode())

def bypass(domain):
    post = urlencode({'cfS': domain})
    result = br.open(
        'http://www.crimeflare.info/cgi-bin/cfsearch.cgi ', post).read()

    match = search(r' \b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', result)
    if match:
        bypass.ip_addr = match.group().split(' ')[1][:-1]
        string='{} Real IP Address : {}'.format(good, bypass.ip_addr)
        logger.writeLog(string.encode())

def dnsdump(domain):
    res = DNSDumpsterAPI(False).search(domain)
    string='\n{} DNS Records'.format(good)
    logger.writeLog(string.encode())
    for entry in res['dns_records']['dns']:
        string='{domain} ({ip}) {as} {provider} {country}'.format(**entry)
        logger.writeLog(string.encode())
    for entry in res['dns_records']['mx']:
        string='\n{} MX Records'.format(good)
        logger.writeLog(string.encode())
        string='{domain} ({ip}) {as} {provider} {country}'.format(**entry)
        logger.writeLog(string.encode())

    string='\n\033[1;32m[+]\033[1;m Host Records (A)'
    logger.writeLog(string.encode())
    for entry in res['dns_records']['host']:
        if entry['reverse_dns']:
            string='{domain} ({reverse_dns}) ({ip}) {as} {provider} {country}'.format(**entry)
        else:
            string='{domain} ({ip}) {as} {provider} {country}'.format(**entry)
        logger.writeLog(string.encode())
    string='\n{} TXT Records'.format(good)
    logger.writeLog(string.encode())
    for entry in res['dns_records']['txt']:
        logger.writeLog(entry.encode())
    string='\n{} DNS Map: https://dnsdumpster.com/static/map/{}.png\n'.format(good, domain.strip('www.'))


def fingerprint(ip_addr):
    try:
        result = br.open('https://www.censys.io/ipv4/%s/raw' % ip_addr).read()
        match = search(r'&#34;os_description&#34;: &#34;[^<]*&#34;', result)
        if match:
            string='{} Operating System : {}'.format(good, match.group().split('n&#34;: &#34;')[1][:-5])
    except:
        pass


ip_addr = socket.gethostbyname(domain)
string='{} IP Address : {}'.format(info, ip_addr)
try:
    r = requests.get(target)
    header = r.headers['Server']
    if 'cloudflare' in header:
        string='{} Cloudflare detected'.format(bad)
        logger.writeLog(string.encode())

        bypass(domain)
        try:
            ip_addr = bypass.ip_addr
        except:
            pass
    else:
        string='{} Server: {}'.format(info, header)
        logger.writeLog(string.encode())
    try:
        string='{} Powered By: {}'.format(info, r.headers['X-Powered-By'])
        logger.writeLog(string.encode())
    except:
        pass
    try:
        r.headers['X-Frame-Options']
    except:
        string='{} Clickjacking protection is not in place.'.format(good)
        logger.writeLog(string.encode())
except:
    pass
fingerprint(ip_addr)
cms(domain)
honeypot(ip_addr)
string="{}----------------------------------------{}".format(red, end)
logger.writeLog(string.encode())

whoisIt(domain)

try:
    r = br.open(target + '/robots.txt').read()
    string='\033[1;31m-\033[1;m' * 40
    string='{} Robots.txt retrieved\n{}'.format(good,r)
except:
    pass
string='\033[1;31m-\033[1;m' * 40
logger.writeLog(string.encode())
nmap(ip_addr)
string='\033[1;31m-\033[1;m' * 40
logger.writeLog(string.encode())
dnsdump(domain)

#now theHarvestLib
harvest=theHarvesterLib.harvester()
harvest.word=domain

logD=harvest.run()
#log the data from theHarvesterLib.run()
for line in logD:
    logger.writeLog(line,ignorePrint=True)

try:
    br.open(target)
    string='{} Crawling the target for fuzzable URLs'.format(run)
    logger.writeLog(string.encode())
    for link in br.links():
        if 'http' in link.url or '=' not in link.url:
            pass
        else:
            url = target + '/' + link.url
            params.append(url)
    if len(params) == 0:
        string='{} No fuzzable URLs found'.format(bad)
        logger.writeLog(string.encode())
        quit()
    string='{} Found {} fuzzable URLs'.format(good, len(params))
    logger.writeLog(string.encode())

    for url in params:
        logger.writeLog(url.encode())
        sqli(url)
        url = url.replace('=', '<svg/onload=alert()>')
        r = br.open(url).read()
        if '<svg/onload=alert()>' in r:
            string='{} One or more parameters are vulnerable to XSS'.format(good)
            logger.writeLog(string.encode())
        break
    string='{} These are the URLs having parameters:'.format(good)
    for url in params:
        logger.writeLog(url.encode())
except:
    pass

if logger.logFile != None:
    logger.actualWrite()
