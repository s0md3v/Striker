#! /usr/bin/env python2

import string,httplib,sys,os
from socket import *
import re,getopt,requests
from discovery import *
from lib import htmlExport
from lib import hostchecker


class harvester:
    limit=100
    word=''
    start=0
    virtual="basic"
    engine='all'
    engines=("baidu","bing","crtsh","bingapi","dogpile","google","googleCSE","virustotal","googleplus","google-profiles","linkdin","pgp","twitter","vhost","yahoo","netcraft","all")
    all_emails=[]
    all_hosts=[]
    host_ip=[]
    vhost=[]
    full=[]
    flashMem=[]
    ERR_ENGINE="{} : engine not supported."
    
    def alphaModule(self):
        string="\033[1;97m[>]\033[1;m Loading Alpha modules (1/3)"
        self.flashMem.append(string)
        print(string)
        search = googlesearch.search_google(self.word,self.limit,self.start)
        search.process()
        emails = search.get_emails()
        hosts = search.get_hostnames()
        self.all_emails.extend(emails)
        self.all_hosts.extend(hosts)

    def betaModule(self):
        string="\033[1;97m[>]\033[1;m Beta module deployed (2/3)"
        self.flashMem.append(string)
        print(string)
        bingapi = "no"
        search = bingsearch.search_bing(self.word,self.limit,self.start)
        search.process(bingapi)
        emails=search.get_emails()
        hosts=search.get_hostnames()
        self.all_emails.extend(emails)
        self.all_hosts.extend(hosts)
    
    def gammaModule(self):
        string="\033[1;97m[>]\033[1;m Gamma module initiated (3/3)"
        self.flashMem.append(string)
        print(string)
        search = exaleadsearch.search_exalead(self.word,self.limit,self.start)
        search.process()
        emails=search.get_emails()
        hosts=search.get_hostnames()
        self.all_emails.extend(emails)
        self.all_hosts.extend(hosts)

    def hostsFound(self):
        string="\n[+] Hosts found in search engines:"
        sep='-'*len(string)

        self.flashMem.append(string)
        self.flashMem.append(sep)
        
        print string
        print sep
        
        all_hosts=sorted(set(self.all_hosts))
        
        string="[-] Resolving IPs from Hostnames... "
        self.flashMem.append(string)
        print(string)
        
        full_host = hostchecker.Checker(self.all_hosts)
        self.full = full_host.check()
        for host in self.full:
            ip = host.split(":")[0]
            self.flashMem.append(host)
            print host
            if not self.host_ip.count(ip.lower()):
                self.host_ip.append(ip.lower())
            else:
                pass

    def vhostSearch(self):
        string="[+] Virtual hosts:"
        sep= '-'*len(string)

        self.flashMem.append(string)
        self.flashMem.append(sep)
        print string
        print sep

        for l in self.host_ip:
            search = bingsearch.search_bing(l,limit,start)
            search.process_vhost()
            res= search.get_allhostnames()
            for x in res:
                x = re.sub(r'[[\<\/\?]*[\w]*>]*','',x)
                x = re.sub('<','',x)
                x = re.sub('>','',x)
                string=l + "\t" + x

                self.flashMem.append(string)
                print string
                
                self.vhost.append(l+":"+x)
                self.full.append(l+":"+x)
        self.vhost=sorted(set(self.vhost))

    def run(self):
        if self.word != '':
            all_emails=[]
            all_hosts=[]
            start=int(self.start)
            host_ip=[]
            filename=''
            binapi="yes"
            dnslookup=False
            dnsbrute=False
            dnstld=False
            shodan=False
            vhost=[]
            virtual=False
            limit=int(self.limit)
            if self.engine not in self.engines:
                sys.exit(self.ERR_ENGINE.format(self.engine))
            else:
                pass
            if self.engine == "all":
                string='\033[1;97m[>]\033[1;m Initiating 3 intel modules'
                self.flashMem.append(string)
                print(string)

                self.alphaModule()
                self.betaModule()
                self.gammaModule()
                
                #clean up email list, sort and uniq
                self.all_emails=sorted(set(all_emails))
            if self.all_emails == []:
                string="no emails found"
                self.flashMem.append(string)
                print string
            else:
                string="\n\n\[+] Emails Found:"
                sep="-"*len(string)
                
                self.flashMem.append(string)
                self.flashMem.append(sep)

                print string
                print sep

                string="\n".join(all_emails)
                self.flashMem.append(string)
                print string
    
            if self.all_hosts == []:
                string="No hosts found"
                self.flashMem.append(string)
                print string
            else:
                self.hostsFound()
            
            if virtual == 'basic':
                self.vhostSearch()        
            else:
                pass
        return self.flashMem
