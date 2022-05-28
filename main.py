import sys
import argparse
import subprocess
import os
import time
import threading
import re
import random
from urllib.parse import urlsplit

CURSOR_UP = '\x1b[1A'
ERASE_ONE_LINE = '\x1b[2K'

time_intervals = (
    ('h', 3600),
    ('m', 60),
    ('s', 1),
)

class output_bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    BADFAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    BG_ERR_TXT = '\033[41m'  # For critical errors and crashes
    BG_HEAD_TXT = '\033[100m'
    BG_ENDL_TXT = '\033[46m'
    BG_CRIT_TXT = '\033[45m'
    BG_HIGH_TXT = '\033[41m'
    BG_MED_TXT = '\033[43m'
    BG_LOW_TXT = '\033[44m'
    BG_INFO_TXT = '\033[42m'

    BG_SCAN_TXT_START = '\x1b[6;30;42m'
    BG_SCAN_TXT_END = '\x1b[0m'

proc_high = output_bcolors.BADFAIL + "●" + output_bcolors.ENDC
proc_med = output_bcolors.WARNING + "●" + output_bcolors.ENDC
proc_low = output_bcolors.OKGREEN + "●" + output_bcolors.ENDC

def terminal_size():
    try:
        rows, columns = subprocess.check_output(['stty', 'size']).split()
        return int(columns)
    except subprocess.CalledProcessError as e:
        return int(20)

class control_program:
    busy = False
    delay = 0.015

    @staticmethod
    def control_program_cursor():
        while 1:
            for cursor in ' ': yield cursor

    def __init__(self, delay=None):
        self.control_program_generator = self.control_program_cursor()
        if delay and float(delay): self.delay = delay
        self.disabled = False

    def control_program_task(self):
        inc = 0
        try:
            while self.busy:
                if not self.disabled:
                    x = output_bcolors.BG_SCAN_TXT_START + next(self.control_program_generator) + output_bcolors.BG_SCAN_TXT_END
                    inc = inc + 1
                    print(x, end='')
                    if inc > random.uniform(0, terminal_size()):  # 30 init
                        print(end="\r")
                        output_bcolors.BG_SCAN_TXT_START = '\x1b[6;30;' + str(round(random.uniform(40, 47))) + 'm'
                        inc = 0
                    sys.stdout.flush()
                time.sleep(self.delay)
                if not self.disabled:
                    sys.stdout.flush()

        except (KeyboardInterrupt, SystemExit):
            print(
                "\n\t" + output_bcolors.BG_ERR_TXT + "CatScanner are Quitting..." + output_bcolors.ENDC)
            sys.exit(1)

    def start(self):
        self.busy = True
        try:
            threading.Thread(target=self.control_program_task).start()
        except Exception as e:
            print("\n")

    def stop(self):
        try:
            self.busy = False
            time.sleep(self.delay)
        except (KeyboardInterrupt, SystemExit):
            print(
                "\n\t" + output_bcolors.BG_ERR_TXT + "CatScanner are Quitting..." + output_bcolors.ENDC)
            sys.exit(1)

control_program = control_program()

# Scanners that will be used and filename rotation (default: enabled (1))
tools_used_on_scanner = [
    # 1
    ["host", "Host - Checks for existence of IPV6 address.", "host", 1],

    # 2
    ["aspnet_config_err", "ASP.Net Misconfiguration - Checks for ASP.Net Misconfiguration.", "wget", 1],

    # 3
    ["wp_check", "WordPress Checker - Checks for WordPress Installation.", "wget", 1],

    # 4
    ["drp_check", "Drupal Checker - Checks for Drupal Installation.", "wget", 1],

    # 5
    ["joom_check", "Joomla Checker - Checks for Joomla Installation.", "wget", 1],

    # 6
    ["uniscan", "Uniscan - Checks for robots.txt & sitemap.xml", "uniscan", 1],

    # 7
    ["wafw00f", "Wafw00f - Checks for Application Firewalls.", "wafw00f", 1],

    # 8
    ["nmap", "Nmap - Fast Scan [Only Few Port Checks]", "nmap", 1],

    # 9
    ["theHarvester", "The Harvester - Scans for emails using Google's passive search.", "theHarvester", 1],

    # 10
    ["dnsrecon", "DNSRecon - Attempts Multiple Zone Transfers on Nameservers.", "dnsrecon", 1],

    # 11
    # ["fierce","Fierce - Attempts Zone Transfer [No Brute Forcing]","fierce",1],

    # 12
    ["dnswalk", "DNSWalk - Attempts Zone Transfer.", "dnswalk", 1],

    # 13
    ["whois", "WHOis - Checks for Administrator's Contact Information.", "whois", 1],

    # 14
    ["nmap_header", "Nmap [XSS Filter Check] - Checks if XSS Protection Header is present.", "nmap", 1],

    # 15
    ["nmap_sloris", "Nmap [Slowloris DoS] - Checks for Slowloris Denial of Service Vulnerability.", "nmap", 1],

    # 16
    ["sslyze_hbleed", "SSLyze - Checks only for Heartbleed Vulnerability.", "sslyze", 1],

    # 17
    ["nmap_hbleed", "Nmap [Heartbleed] - Checks only for Heartbleed Vulnerability.", "nmap", 1],

    # 18
    ["nmap_poodle", "Nmap [POODLE] - Checks only for Poodle Vulnerability.", "nmap", 1],

    # 19
    ["nmap_ccs", "Nmap [OpenSSL CCS Injection] - Checks only for CCS Injection.", "nmap", 1],

    # 20
    ["nmap_freak", "Nmap [FREAK] - Checks only for FREAK Vulnerability.", "nmap", 1],

    # 21
    ["nmap_logjam", "Nmap [LOGJAM] - Checks for LOGJAM Vulnerability.", "nmap", 1],

    # 22
    ["sslyze_ocsp", "SSLyze - Checks for OCSP Stapling.", "sslyze", 1],

    # 23
    ["sslyze_zlib", "SSLyze - Checks for ZLib Deflate Compression.", "sslyze", 1],

    # 24
    ["sslyze_reneg", "SSLyze - Checks for Secure Renegotiation Support and Client Renegotiation.", "sslyze", 1],

    # 25
    ["sslyze_resum", "SSLyze - Checks for Session Resumption Support with [Session IDs/TLS Tickets].", "sslyze", 1],

    # 26
    ["lbd", "LBD - Checks for DNS/HTTP Load Balancers.", "lbd", 1],

    # 27
    ["golismero_dns_malware", "Golismero - Checks if the domain is spoofed or hijacked.", "golismero", 1],

    # 28
    ["golismero_heartbleed", "Golismero - Checks only for Heartbleed Vulnerability.", "golismero", 1],

    # 29
    ["golismero_brute_url_predictables", "Golismero - BruteForces for certain files on the Domain.", "golismero", 1],

    # 30
    ["golismero_brute_directories", "Golismero - BruteForces for certain directories on the Domain.", "golismero", 1],

    # 31
    ["golismero_sqlmap", "Golismero - SQLMap [Retrieves only the DB Banner]", "golismero", 1],

    # 32
    ["dirb", "DirB - Brutes the target for Open Directories.", "dirb", 1],

    # 33
    ["xsser", "XSSer - Checks for Cross-Site Scripting [XSS] Attacks.", "xsser", 1],

    # 34
    ["golismero_ssl_scan", "Golismero SSL Scans - Performs SSL related Scans.", "golismero", 1],

    # 35
    ["golismero_zone_transfer", "Golismero Zone Transfer - Attempts Zone Transfer.", "golismero", 1],

    # 36
    ["golismero_nikto", "Golismero Nikto Scans - Uses Nikto Plugin to detect vulnerabilities.", "golismero", 1],

    # 37
    ["golismero_brute_subdomains", "Golismero Subdomains Bruter - Brute Forces Subdomain Discovery.", "golismero", 1],

    # 38
    ["dnsenum_zone_transfer", "DNSEnum - Attempts Zone Transfer.", "dnsenum", 1],

    # 39
    ["fierce_brute_subdomains", "Fierce Subdomains Bruter - Brute Forces Subdomain Discovery.", "fierce", 1],

    # 40
    ["dmitry_email", "DMitry - Passively Harvests Emails from the Domain.", "dmitry", 1],

    # 41
    ["dmitry_subdomains", "DMitry - Passively Harvests Subdomains from the Domain.", "dmitry", 1],

    # 42
    ["nmap_telnet", "Nmap [TELNET] - Checks if TELNET service is running.", "nmap", 1],

    # 43
    ["nmap_ftp", "Nmap [FTP] - Checks if FTP service is running.", "nmap", 1],

    # 44
    ["nmap_stuxnet", "Nmap [STUXNET] - Checks if the host is affected by STUXNET Worm.", "nmap", 1],

    # 45
    ["webdav", "WebDAV - Checks if WEBDAV enabled on Home directory.", "davtest", 1],

    # 46
    ["golismero_finger", "Golismero - Does a fingerprint on the Domain.", "golismero", 1],

    # 47
    ["uniscan_filebrute", "Uniscan - Brutes for Filenames on the Domain.", "uniscan", 1],

    # 48
    ["uniscan_dirbrute", "Uniscan - Brutes Directories on the Domain.", "uniscan", 1],

    # 49
    ["uniscan_ministresser", "Uniscan - Stress Tests the Domain.", "uniscan", 1],

    # 50
    ["uniscan_rfi", "Uniscan - Checks for LFI, RFI and RCE.", "uniscan", 1],

    # 51
    ["uniscan_xss", "Uniscan - Checks for XSS, SQLi, BSQLi & Other Checks.", "uniscan", 1],

    # 52
    ["nikto_xss", "Nikto - Checks for Apache Expect XSS Header.", "nikto", 1],

    # 53
    ["nikto_subrute", "Nikto - Brutes Subdomains.", "nikto", 1],

    # 54
    ["nikto_shellshock", "Nikto - Checks for Shellshock Bug.", "nikto", 1],

    # 55
    ["nikto_internalip", "Nikto - Checks for Internal IP Leak.", "nikto", 1],

    # 56
    ["nikto_putdel", "Nikto - Checks for HTTP PUT DEL.", "nikto", 1],

    # 57
    ["nikto_headers", "Nikto - Checks the Domain Headers.", "nikto", 1],

    # 58
    ["nikto_ms01070", "Nikto - Checks for MS10-070 Vulnerability.", "nikto", 1],

    # 59
    ["nikto_servermsgs", "Nikto - Checks for Server Issues.", "nikto", 1],

    # 60
    ["nikto_outdated", "Nikto - Checks if Server is Outdated.", "nikto", 1],

    # 61
    ["nikto_httpoptions", "Nikto - Checks for HTTP Options on the Domain.", "nikto", 1],

    # 62
    ["nikto_cgi", "Nikto - Enumerates CGI Directories.", "nikto", 1],

    # 63
    ["nikto_ssl", "Nikto - Performs SSL Checks.", "nikto", 1],

    # 64
    ["nikto_sitefiles", "Nikto - Checks for any interesting files on the Domain.", "nikto", 1],

    # 65
    ["nikto_paths", "Nikto - Checks for Injectable Paths.", "nikto", 1],

    # 66
    ["dnsmap_brute", "DNSMap - Brutes Subdomains.", "dnsmap", 1],

    # 67
    ["nmap_sqlserver", "Nmap - Checks for MS-SQL Server DB", "nmap", 1],

    # 68
    ["nmap_mysql", "Nmap - Checks for MySQL DB", "nmap", 1],

    # 69
    ["nmap_oracle", "Nmap - Checks for ORACLE DB", "nmap", 1],

    # 70
    ["nmap_rdp_udp", "Nmap - Checks for Remote Desktop Service over UDP", "nmap", 1],

    # 71
    ["nmap_rdp_tcp", "Nmap - Checks for Remote Desktop Service over TCP", "nmap", 1],

    # 72
    ["nmap_full_ps_tcp", "Nmap - Performs a Full TCP Port Scan", "nmap", 1],

    # 73
    ["nmap_full_ps_udp", "Nmap - Performs a Full UDP Port Scan", "nmap", 1],

    # 74
    ["nmap_snmp", "Nmap - Checks for SNMP Service", "nmap", 1],

    # 75
    ["aspnet_elmah_axd", "Checks for ASP.net Elmah Logger", "wget", 1],

    # 76
    ["nmap_tcp_smb", "Checks for SMB Service over TCP", "nmap", 1],

    # 77
    ["nmap_udp_smb", "Checks for SMB Service over UDP", "nmap", 1],

    # 78
    ["wapiti", "Wapiti - Checks for SQLi, RCE, XSS and Other Vulnerabilities", "wapiti", 1],

    # 79
    ["nmap_iis", "Nmap - Checks for IIS WebDAV", "nmap", 1],

    # 80
    ["whatweb", "WhatWeb - Checks for X-XSS Protection Header", "whatweb", 1],

    # 81
    ["amass", "AMass - Brutes Domain for Subdomains", "amass", 1]
]

tool_init_on_cmd = [
    # 1
    ["host ", ""],

    # 2
    ["wget -O /tmp/rapidscan_temp_aspnet_config_err --tries=1 ", "/%7C~.aspx"],

    # 3
    ["wget -O /tmp/rapidscan_temp_wp_check --tries=1 ", "/wp-admin"],

    # 4
    ["wget -O /tmp/rapidscan_temp_drp_check --tries=1 ", "/user"],

    # 5
    ["wget -O /tmp/rapidscan_temp_joom_check --tries=1 ", "/administrator"],

    # 6
    ["uniscan -e -u ", ""],

    # 7
    ["wafw00f ", ""],

    # 8
    ["nmap -F --open -Pn ", ""],

    # 9
    ["theHarvester -l 50 -b google -d ", ""],

    # 10
    ["dnsrecon -d ", ""],

    # 11
    # ["fierce -wordlist xxx -dns ",""],

    # 12
    ["dnswalk -d ", "."],

    # 13
    ["whois ", ""],

    # 14
    ["nmap -p80 --script http-security-headers -Pn ", ""],

    # 15
    ["nmap -p80,443 --script http-slowloris --max-parallelism 500 -Pn ", ""],

    # 16
    ["sslyze --heartbleed ", ""],

    # 17
    ["nmap -p443 --script ssl-heartbleed -Pn ", ""],

    # 18
    ["nmap -p443 --script ssl-poodle -Pn ", ""],

    # 19
    ["nmap -p443 --script ssl-ccs-injection -Pn ", ""],

    # 20
    ["nmap -p443 --script ssl-enum-ciphers -Pn ", ""],

    # 21
    ["nmap -p443 --script ssl-dh-params -Pn ", ""],

    # 22
    ["sslyze --certinfo=basic ", ""],

    # 23
    ["sslyze --compression ", ""],

    # 24
    ["sslyze --reneg ", ""],

    # 25
    ["sslyze --resum ", ""],

    # 26
    ["lbd ", ""],

    # 27
    ["golismero -e dns_malware scan ", ""],

    # 28
    ["golismero -e heartbleed scan ", ""],

    # 29
    ["golismero -e brute_url_predictables scan ", ""],

    # 30
    ["golismero -e brute_directories scan ", ""],

    # 31
    ["golismero -e sqlmap scan ", ""],

    # 32
    ["dirb http://", " -fi"],

    # 33
    ["xsser --all=http://", ""],

    # 34
    ["golismero -e sslscan scan ", ""],

    # 35
    ["golismero -e zone_transfer scan ", ""],

    # 36
    ["golismero -e nikto scan ", ""],

    # 37
    ["golismero -e brute_dns scan ", ""],

    # 38
    ["dnsenum ", ""],

    # 39
    ["fierce --domain ", ""],

    # 40
    ["dmitry -e ", ""],

    # 41
    ["dmitry -s ", ""],

    # 42
    ["nmap -p23 --open -Pn ", ""],

    # 43
    ["nmap -p21 --open -Pn ", ""],

    # 44
    ["nmap --script stuxnet-detect -p445 -Pn ", ""],

    # 45
    ["davtest -url http://", ""],

    # 46
    ["golismero -e fingerprint_web scan ", ""],

    # 47
    ["uniscan -w -u ", ""],

    # 48
    ["uniscan -q -u ", ""],

    # 49
    ["uniscan -r -u ", ""],

    # 50
    ["uniscan -s -u ", ""],

    # 51
    ["uniscan -d -u ", ""],

    # 52
    ["nikto -Plugins 'apache_expect_xss' -host ", ""],

    # 53
    ["nikto -Plugins 'subdomain' -host ", ""],

    # 54
    ["nikto -Plugins 'shellshock' -host ", ""],

    # 55
    ["nikto -Plugins 'cookies' -host ", ""],

    # 56
    ["nikto -Plugins 'put_del_test' -host ", ""],

    # 57
    ["nikto -Plugins 'headers' -host ", ""],

    # 58
    ["nikto -Plugins 'ms10-070' -host ", ""],

    # 59
    ["nikto -Plugins 'msgs' -host ", ""],

    # 60
    ["nikto -Plugins 'outdated' -host ", ""],

    # 61
    ["nikto -Plugins 'httpoptions' -host ", ""],

    # 62
    ["nikto -Plugins 'cgi' -host ", ""],

    # 63
    ["nikto -Plugins 'ssl' -host ", ""],

    # 64
    ["nikto -Plugins 'sitefiles' -host ", ""],

    # 65
    ["nikto -Plugins 'paths' -host ", ""],

    # 66
    ["dnsmap ", ""],

    # 67
    ["nmap -p1433 --open -Pn ", ""],

    # 68
    ["nmap -p3306 --open -Pn ", ""],

    # 69
    ["nmap -p1521 --open -Pn ", ""],

    # 70
    ["nmap -p3389 --open -sU -Pn ", ""],

    # 71
    ["nmap -p3389 --open -sT -Pn ", ""],

    # 72
    ["nmap -p1-65535 --open -Pn ", ""],

    # 73
    ["nmap -p1-65535 -sU --open -Pn ", ""],

    # 74
    ["nmap -p161 -sU --open -Pn ", ""],

    # 75
    ["wget -O /tmp/rapidscan_temp_aspnet_elmah_axd --tries=1 ", "/elmah.axd"],

    # 76
    ["nmap -p445,137-139 --open -Pn ", ""],

    # 77
    ["nmap -p137,138 --open -Pn ", ""],

    # 78
    ["wapiti ", " -f txt -o rapidscan_temp_wapiti"],

    # 79
    ["nmap -p80 --script=http-iis-webdav-vuln -Pn ", ""],

    # 80
    ["whatweb ", " -a 1"],

    # 81
    ["amass enum -d ", ""]
]

tools = [
    ["wapiti"], ["whatweb"], ["nmap"], ["golismero"], ["host"], ["wget"], ["uniscan"], ["wafw00f"], ["dirb"],
    ["davtest"], ["theHarvester"], ["xsser"], ["dnsrecon"], ["fierce"], ["dnswalk"], ["whois"], ["sslyze"], ["lbd"],
    ["golismero"], ["dnsenum"], ["dmitry"], ["davtest"], ["nikto"], ["dnsmap"], ["amass"]
]
