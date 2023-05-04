import hashlib
import json
import os
import random
import shutil
import string

import fire
import datetime
from loguru import logger
from core.tools.domain import domain_main
from core.tools.finger import finger_main
from core.tools.sensitiveinfo import sensitiveinfo_main
from core.tools.vulscan import vulscan_main
from core.tools.portscan import portscan_main
from core.download import download_tools

# from common.getconfig import *
# import common


yellow = '\033[01;33m'
white = '\033[01;37m'
green = '\033[01;32m'
blue = '\033[01;34m'
red = '\033[1;31m'
end = '\033[0m'

version = 'v1.0'
message = white + '{' + red + version + ' #dev' + white + '}'

banner = f"""

████████╗ █████╗ ██████╗  ██████╗ {message}{green}
╚══██╔══╝██╔══██╗██╔══██╗██╔═══██╗
   ██║   ███████║██████╔╝██║   ██║{blue}
   ██║   ██╔══██║██╔══██╗██║   ██║
   ██║   ██║  ██║██║  ██║╚██████╔╝
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ {white} By t5463
{end}                                  
"""


# all_config = getconfig()
# Xray_Port = int(all_config['tools']['other']['xray']['listenport'])


def create_logfile():
    if os.path.exists(f'{os.getcwd()}/log') is False:
        os.makedirs(f'{os.getcwd()}/log')
    logger.add(sink='log/runtime.log', level='INFO', encoding='utf-8')
    logger.add(sink='log/error.log', level='ERROR', encoding='utf-8')


# json
def progress_record(date=None, module=None, value=None):
    logfile = f"result/{date}/log.json"
    if os.path.exists(logfile) is False:
        shutil.copy("config/log_template.json", f"result/{date}/log.json")
    with open(logfile, 'r', encoding='utf-8') as f1:
        log_json = json.loads(f1.read())
    log_json[module] = value
    with open(logfile, "w", encoding="utf-8") as f:
        f.write(json.dumps(log_json))
    return True
    # if module in dict(log_json).keys() and target:


class taro(object):
    '''

    taro help summary page

    taro is an automated scanning tool set

    mode:
    install     Download the required tools
    all         all scan and attack:subdomain, survival detection, finger, portscan, email collect, sensitive(crawl urls), pocscan, Weak password scanning, to_xray
        --domain    one domain
        --domains   a domain file
    all2        run scan and attack except domain collection: survival detection, finger, portscan, email collect, sensitive(crawl urls), pocscan, Weak password scanning, to_xray
        --subdomain    one subdomain
        --subdomains   a subdomain file
    collect     run all collection modules :subdomain, survival detection, finger, port, email collect, sensitive(crawl urls), pocscan, to_xray
        --domain    one domain
        --domains   a domain file
    collect1    run collection modules :subdomain, survival detection, finger
        --domain    one domain
        --domains   a domain file
    collect2    run collection modules :subdomain, survival detection, finger, portscan
        --domain    one domain
        --domains   a domain file
    subdomain   only collect subdomain
        --domain    one domain
        --domains   a domains file
    finger      only collect the survival URL and  fingerprint
        --url       one url
        --urls      an urls file
    portscan    only collect port from ip or ips
        --ip        one ip
        --ips       an ips file
    sensitive   only collect directory with crawl,email
        --url       one url
        --urls      an urls file
    webattack   only attack web from url or urls: pocscan, Weak password scanning, crawl urls to xray
        --url       one url
        --urls      an urls file
    webattack2  only poc scan from url or urls: pocscan, Weak password scanning
        --url       one url
        --urls      an urls file
    hostattack  only attack ip from ip or ips
        --ip        one ip
        --ips       an ips file
    attack      run webattack and hostattack: crawl url to xray, pocscan, Weak password scanning


    Example:
        python3 taro.py install
        python3 taro.py --domain example.com all
        python3 taro.py --domains ./domains.txt all
        python3 taro.py --domain example.com collect
        python3 taro.py --domains ./domains.txt collect
        python3 taro.py --domain example.com collect1
        python3 taro.py --domains ./domains.txt collect1
        python3 taro.py --domain example.com collect2
        python3 taro.py --domains ./domains.txt collect2
        python3 taro.py --domain example.com subdomain
        python3 taro.py --domains ./domains.txt subdomain

        python3 taro.py --subdomain aaa.example.com all2
        python3 taro.py --subdomains ./subdomains.txt all2

        python3 taro.py --url http://example.com finger
        python3 taro.py --urls ./urls.txt finger
        python3 taro.py --url http://example.com sensitive
        python3 taro.py --urls ./urls.txt sensitive
        python3 taro.py --url http://example.com webattack
        python3 taro.py --urls ./urls.txt webattack
        python3 taro.py --url http://example.com webattack2
        python3 taro.py --urls ./urls.txt webattack2

        python3 taro.py --ip example.com portscan
        python3 taro.py --ips ./domains.txt portscan
        python3 taro.py --ip example.com hostattack
        python3 taro.py --ips ./domains.txt hostattack


    :param domain:
    :param domains:
    :param subdomain:
    :param subdomains:
    :param url:
    :param urls:
    :param ip:
    :param ips:
    :param attackflag:
    :param date:
    '''

    def __init__(self, domain=None, domains=None, subdomain=None, subdomains=None, url=None, urls=None, ip=None,
                 ips=None, attackflag=False, date=None, proxy=None):

        date1 = str(datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S"))
        self.domain = domain
        self.domains = domains  # domainsfile
        self.subdomain = subdomain
        self.subdomains = subdomains
        self.url = url
        self.urlsfile = urls
        self.ip = ip
        self.ips = ips
        self.attackflag = attackflag
        self.date = date if date else date1
        self.proxy = proxy
        self.domains_list = []
        # self.command = "python3 taro.py"
        self.params = {
            "domain": self.domain,
            "domains": self.domains,
            "subdomain": self.subdomain,
            "subdomains": self.subdomains,
            "url": self.url,
            "urls": self.urlsfile,
            "ip": self.ip,
            "ips": self.ips,
            "attackflag": self.attackflag,
            "date": self.date
        }
        # for i in [self.domain,self.domains,self.subdomain,self.subdomains,self.url,self.urlsfile,self.ip,self.ips,self.date]:
        #     if i is not None:
        #         self.command += "--{}".format(i)
        create_logfile()
        print(banner)
        self.randomstr = hashlib.md5(bytes(self.date, encoding='utf-8')).hexdigest()
        
        self.result_folder = f"result/{self.date}"
        if os.path.exists(self.result_folder) is False:
            os.makedirs(self.result_folder)

        if self.domain and self.domains is None:
            self.domains_list.append(self.domain)
        elif self.domains and self.domain is None:
            with open(self.domains, 'r', encoding='utf-8') as f:
                for line in f.readlines():
                    line = line.strip()
                    self.domains_list.append(line)
            self.domains_list = list(set(self.domains_list))
        elif self.subdomain and self.subdomains is None:
            with open(f"result/{self.date}/{self.randomstr}.final.subdomains.txt", "w", encoding="utf-8") as f:
                f.write(str(self.subdomain))
        elif self.subdomains and self.subdomain is None:
            if os.path.exists(self.subdomains):
                shutil.copy(self.subdomains, f"result/{self.date}/{self.randomstr}.final.subdomains.txt")
            else:
                logger.error(f"[-] {self.subdomains} Not found and exit!")
                exit(1)


        if self.domains is not None:
            if os.path.isabs(self.domains) is False:
                newpath = os.path.realpath(os.getcwd() + '/' + self.domains)
                if os.path.exists(newpath):
                    self.domains = newpath
        if self.urlsfile is not None:
            if os.path.isabs(self.urlsfile) is False:
                newpath = os.path.realpath(os.getcwd() + '/' + self.urlsfile)
                if os.path.exists(newpath):
                    self.urlsfile = newpath
        if self.ips is not None:
            if os.path.isabs(self.ips) is False:
                newpath = os.path.realpath(os.getcwd() + '/' + self.ips)
                if os.path.exists(newpath):
                    self.ips = newpath

        progress_record(self.date, "date", self.date)
        progress_record(self.date, "params", self.params)

    def install(self):
        # download tools
        dd = download_tools.Download(proxy=self.proxy)
        dd.run()

    def subdomain(self):
        # self.command += "--{}".format(self.subdomain)
        if self.domains_list:
            for domain in self.domains_list:
                domain_main.manager(domain=domain, date=self.date)
        else:
            logger.error("[-] Please check --domain or --domains")

    def finger(self):
        if self.url:
            finger_main.manager(domain=None, url=self.url, urlsfile=None, date=self.date)
        elif self.urlsfile:
            finger_main.manager(domain=None, url=None, urlsfile=self.urlsfile, date=self.date)
        else:
            logger.error("[-] Please check --url or --urls")

    def portscan(self):
        if self.ip:
            portscan_main.manager(domain=None, ip=self.ip, ipfile=None, date=self.date)
        elif self.ips:
            portscan_main.manager(domain=None, ip=None, ipfile=self.ips, date=self.date)
        else:
            logger.error("[-] Please check --ip or --ips")


    def sensitive(self):
        self.attackflag = False
        if self.url:
            sensitiveinfo_main.manager(domain=None, url=self.url, urlsfile=None, attackflag=self.attackflag,
                                       date=self.date)
        elif self.urlsfile:
            sensitiveinfo_main.manager(domain=None, url=None, urlsfile=self.urlsfile, attackflag=self.attackflag,
                                       date=self.date)
        else:
            logger.error("[-] Please check --url or --urls")


    def webattack(self):
        self.attackflag = True
        if self.url:
            sensitiveinfo_main.manager(domain=None, url=self.url, urlsfile=None, attackflag=self.attackflag,
                                       date=self.date)  # toxray
            vulscan_main.webmanager(domain=None, url=self.url, urlsfile=None, date=self.date)
        elif self.urlsfile:
            sensitiveinfo_main.manager(domain=None, url=None, urlsfile=self.urlsfile, attackflag=self.attackflag,
                                       date=self.date)
            vulscan_main.webmanager(domain=None, url=None, urlsfile=self.urlsfile, date=self.date)
        else:
            logger.error("[-] Please check --url or --urls")

    def webattack1(self):
        self.attackflag = True
        if self.url:
            sensitiveinfo_main.manager(domain=None, url=self.url, urlsfile=None, attackflag=self.attackflag,
                                       date=self.date)  # toxray
        elif self.urlsfile:
            sensitiveinfo_main.manager(domain=None, url=None, urlsfile=self.urlsfile, attackflag=self.attackflag,
                                       date=self.date)
        else:
            logger.error("[-] Please check --url or --urls")

    # only poc scan
    def webattack2(self):
        self.attackflag = True
        if self.url:
            vulscan_main.webmanager(domain=None, url=self.url, urlsfile=None, date=self.date)
        elif self.urlsfile:
            vulscan_main.webmanager(domain=None, url=None, urlsfile=self.urlsfile, date=self.date)
        else:
            logger.error("[-] Please check --url or --urls")


    def hostattack(self):
        self.attackflag = True
        if self.ip:
            vulscan_main.hostmanager(domain=None, ip=self.ip, ipfile=None, date=self.date)
            # sensitiveinfo_main.manager(domain=None, url=self.url, urlsfile=None, attackflag=self.attackflag,
            #                            date=self.date)
        elif self.ips:
            vulscan_main.hostmanager(domain=None, ip=None, ipfile=self.ips, date=self.date)
        else:
            logger.error("[-] Please check --ip or --ips")

    def attack(self):
        self.webattack()
        self.hostattack()


    def collect(self):
        '''
        python main.py --domain tiqianle.com collect
        python main.py --domains file collect
        :return:
        '''
        self.attackflag = False
        if self.domains_list:
            for domain in self.domains_list:
                domain_main.manager(domain=domain, date=self.date)
                finger_main.manager(domain=domain, url=None, urlsfile=None, date=self.date)
                portscan_main.manager(domain=domain, ip=None, ipfile=None, date=self.date)
                sensitiveinfo_main.manager(domain=domain, url=None, urlsfile=None, attackflag=self.attackflag,
                                           date=self.date)
                # vulscan_main.webmanager(domain=self.domain, url=None, urlsfile=None, date=self.date)
        else:
            logger.error("[-] Please check --domain or --domains")

    def collect1(self):
        # self.attackflag = False
        if self.domains_list:
            for domain in self.domains_list:
                domain_main.manager(domain=domain, date=self.date)
                finger_main.manager(domain=domain, url=None, urlsfile=None, date=self.date)
                # portscan_main.manager(domain=domain, ip=None, ipfile=None, date=self.date)
        else:
            logger.error("[-] Please check --domain or --domains")

    def collect2(self):
        # self.attackflag = False
        if self.domains_list:
            for domain in self.domains_list:
                domain_main.manager(domain=domain, date=self.date)
                finger_main.manager(domain=domain, url=None, urlsfile=None, date=self.date)
                portscan_main.manager(domain=domain, ip=None, ipfile=None, date=self.date)
        else:
            logger.error("[-] Please check --domain or --domains")

    # all_scan
    def all(self):
        '''
        python main.py --domain tiqianle.com all
        python main.py --domains tiqianle.com all
        :return:
        '''
        self.attackflag = True
        if self.domains_list:
            for domain in self.domains_list:
                domain_main.manager(domain=domain, date=self.date)
                finger_main.manager(domain=domain, urlsfile=None, date=self.date)
                portscan_main.manager(domain=domain, ip=None, ipfile=None, date=self.date)
                vulscan_main.webmanager(domain=domain, url=None, urlsfile=None, date=self.date)
                vulscan_main.hostmanager(domain=domain, ip=None, ipfile=None, date=self.date)
                sensitiveinfo_main.manager(domain=domain, url=None, urlsfile=None, attackflag=self.attackflag,
                                           date=self.date)
        else:
            logger.error("[-] Please check --domain or --domains")


    def all2(self):
        '''
        python main.py --subdomain aaa.tiqianle.com all2
        python main.py --subdomains tiqianle.com.txt all2
        :return:
        '''
        self.attackflag = True
        if self.subdomain or self.subdomains:
            # for domain in self.domains_list:
            # domain_main.manager(domain=domain, date=self.date)
            finger_main.manager(domain=self.randomstr, urlsfile=None, date=self.date)
            portscan_main.manager(domain=self.randomstr, ip=None, ipfile=None, date=self.date)
            vulscan_main.webmanager(domain=self.randomstr, url=None, urlsfile=None, date=self.date)
            vulscan_main.hostmanager(domain=self.randomstr, ip=None, ipfile=None, date=self.date)
            sensitiveinfo_main.manager(domain=self.randomstr, url=None, urlsfile=None, attackflag=self.attackflag,
                                       date=self.date)
        else:
            logger.error("[-] Please check --subdomain or --subdomains")


if __name__ == '__main__':
    fire.Fire(taro)