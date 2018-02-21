#!/usr/bin/env python

import string
import httplib
import sys
import os
from socket import *
import re
import getopt
import requests

from discovery import *
from lib import htmlExport
from lib import hostchecker


def usage():

    comm = os.path.basename(sys.argv[0])

    if os.path.dirname(sys.argv[0]) == os.getcwd():
        comm = "./" + comm


def start(argv):
    if len(sys.argv) < 4:
        sys.exit()
    try:
        opts, args = getopt.getopt(argv, "l:d:b:s:vf:nhcte:")
    except getopt.GetoptError:
        sys.exit()
    start = 0
    host_ip = []
    filename = ""
    bingapi = "yes"
    dnslookup = False
    dnsbrute = False
    dnstld = False
    shodan = False
    vhost = []
    virtual = False
    limit = 100
    dnsserver = ""
    for opt, arg in opts:
        if opt == '-l':
            limit = int(arg)
        elif opt == '-d':
            word = arg
        elif opt == '-s':
            start = int(arg)
        elif opt == '-v':
            virtual = "basic"
        elif opt == '-b':
            engine = arg
            if engine not in ("baidu", "bing", "crtsh", "bingapi", "dogpile", "google", "googleCSE", "virustotal", "googleplus", "google-profiles", "linkedin", "pgp", "twitter", "vhost", "yahoo", "netcraft", "all"):
                usage()
                sys.exit()
            else:
                pass
    if engine == "all":
        all_emails = []
        all_hosts = []
        virtual = "basic"
        print '\033[1;97m[>]\033[1;m Initiating 3 intel modules'
        print "\033[1;97m[>]\033[1;m Loading Alpha module (1/3)"
        search = googlesearch.search_google(word, limit, start)
        search.process()
        emails = search.get_emails()
        hosts = search.get_hostnames()
        all_emails.extend(emails)
        all_hosts.extend(hosts)

        print "\033[1;97m[>]\033[1;m Beta module deployed (2/3)"
        bingapi = "no"
        search = bingsearch.search_bing(word, limit, start)
        search.process(bingapi)
        emails = search.get_emails()
        hosts = search.get_hostnames()
        all_hosts.extend(hosts)
        all_emails.extend(emails)

        print "\033[1;97m[>]\033[1;m Gamma module initiated (3/3)"
        search = exaleadsearch.search_exalead(word, limit, start)
        search.process()
        emails = search.get_emails()
        hosts = search.get_hostnames()
        all_hosts.extend(hosts)
        all_emails.extend(emails)

        # Clean up email list, sort and uniq
        all_emails = sorted(set(all_emails))
    #Results############################################################
    if all_emails == []:
        print "No emails found"
    else:
        print "\n\n[+] Emails found:"
        print "------------------"
        print "\n".join(all_emails)

    if all_hosts == []:
        print "No hosts found"
    else:
        print "\n[+] Hosts found in search engines:"
        print "------------------------------------"
        all_hosts = sorted(set(all_hosts))
        print "[-] Resolving hostnames IPs... "
        full_host = hostchecker.Checker(all_hosts)
        full = full_host.check()
        for host in full:
            ip = host.split(':')[0]
            print host
            if host_ip.count(ip.lower()):
                pass
            else:
                host_ip.append(ip.lower())

    #Virtual hosts search###############################################
    if virtual == "basic":
        print "[+] Virtual hosts:"
        print "-----------------"
        for l in host_ip:
            search = bingsearch.search_bing(l, limit, start)
            search.process_vhost()
            res = search.get_allhostnames()
            for x in res:
                x = re.sub(r'[[\<\/?]*[\w]*>]*', '', x)
                x = re.sub('<', '', x)
                x = re.sub('>', '', x)
                print l + "\t" + x
                vhost.append(l + ":" + x)
                full.append(l + ":" + x)
        vhost = sorted(set(vhost))
    else:
        pass


if __name__ == "__main__":
    try:
        start(sys.argv[1:])
    except KeyboardInterrupt:
        print "Search interrupted by user.."
    except:
        sys.exit()
