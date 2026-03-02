#!/usr/bin/python3
import aiohttp
import argparse
import asyncio
import binascii
import bs4
import ipaddress
import json
import os
import re
import requests
import shutil
import socket
import sys
import ssl
import sqlite3
import time
import tldextract
import urllib.parse
import urllib3
import warnings

from bs4 import BeautifulSoup
from bs4 import MarkupResemblesLocatorWarning
from colorama import Fore, Back, Style
from http.client import HTTPConnection
from pprint import pprint
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse
from urllib.parse import quote
from yarl import URL

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", "ssl.wrap_socket", DeprecationWarning)
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

print (Style.RESET_ALL + Fore.MAGENTA + Style.NORMAL)
print ('🐇🐇🐇 Presented by Lost Rabbit Labs 🐇🐇🐇')
print (Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)
print('8   8  8          8""""8                   ')
print('8   8  8 e  eeeee 8    8 e   e eeeee eeeee ')
print('8e  8  8 8  8   " 8    8 8   8 8   8 8   " ')
print('88  8  8 8e 8eeee 8    8 8e  8 8eee8 8eeee ')
print('88  8  8 88    88 8 ___8 88  8 88  8    88 ')
print('88ee8ee8 88 8ee88 8e8888 88ee8 88  8 8ee88\n')
print('ˆˆˆˆˆˆˆˆ ˆˆ ˆˆˆˆˆ ˆˆˆˆˆˆ ˆˆˆˆˆ ˆˆ  ˆ ˆˆˆˆˆ')
print(' Web Scanner & Anomaly Detector (v2.20.2026)')

# Main Settings
enum_payloads = [
    "/",
    "%2f",
    "%2f%2f",
    "%2e",
    "%2e%2e",
    "robots.txt",
    "index.html",
    "index.htm",
    "index.shtml",
    "index.php",
    "index.jsp",
    "index.asp",
    "index.aspx",
    "default.asp",
    "default.aspx",
    "home.asp",
    "home.aspx",
    "aspnet_files/",
    "aspnet_client/",
    "web.config",
    "trace.axd",
    "xyz/abc",
    "test/",
    "test.html",
    "test.php",
    "test.jsp",
    "code/",
    "admin/",
    "temp/",
    "tmp/",
    "uploads/",
    "bin/",
    "files/",
    "webdav/",
    "manager/",
    "logs/",
    "ghost/",
    "jmx-console",
    "phpMyAdmin/",
    "INSTALL.mysql.txt",
    "INSTALL.txt",
    "UPGRADE.txt",
    "LICENSE.txt",
    "LICENSE",
    "wp-login.php",
    "README",
    "WEB-INF/",
    "server-status",
    "server-info",
    "balancer-manager",
    "config.php",
    "xmlrpc.php",
    "sitemap.xml",
    "login.php",
    "console",
    "status",
    "error",
    "phpinfo.php",
    "info.php",
    "access_log",
    "php.ini",
    ".git",
    ".git/",
    ".git/HEAD",
    ".htaccess",
    ".htpasswd",
    ".mysql_history",
    ".bashrc",
    ".ssh",
    ".history",
    ".passwd",
    "passwd",
    ".hta",
    "?id=0",
    ".env",
    "api/",
    "%",
    "%%",
    "&",
    "<script>alert(1)</script>",
    "cgi-bin",
    "webmail",
    "nginx_status",
    "?url=",
    "redirect",
    "{",
    "}",
    "%7b",
    "`",
    "'or '1'='1",
    "~",
    ",",
    "%00",
    "%c0",
    "%p",
    "%20X",
    "%20H",
    "package.json",
    "manifest.json",
    "elmah.axd",
    "public/",
    "_vti_pvt/service.cnf",
    "login?next=/",
    "WS_FTP.LOG",
    "login.asp.bak",
    "?q=1' or '1'='1",
    "z'%3balert(1)%2f%2f157",
    ".well-known/",
    "../../../etc/passwd",
    "favicon.ico",
    "graphql",
    r'?\[',
    "../../../etc/passwd%00",
    r'\..\..\..\windows\win.ini',
    "/../../../windows/win.ini",
    "?target=https://127.0.0.1",
    '0'*20000
]
verbs = [
    "OPTIONS",
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "HEAD",
    "DELETE",
    "CONNECT",
    "TEST",
    "TRACK",
    "TRACE",
    "PROPFIND",
    "PROPPATCH",
    "MKCOL",
    "COPY",
    "MOVE",
    "LOCK",
    "UNLOCK",
    "HELP",
    "SEARCH",
    "ACL",
    "UPDATE",
    "LINK",
    "QUERY",
    "UNBIND"
]
enum_hosts = [
    "localhost",
    "127.0.0.1",
    "127.0.1.1",
    "null",
    "test",
    "0",
    "-1",
    "admin",
    "root",
    "65535",
    "65536",
    "%00",
    " "
]
protos = [
    '0.9',
    '1.0',
    '1.1',
    '2',
    '3'
]

status_color_map = {
    "200": Fore.GREEN,
    "301": Fore.CYAN, "302": Fore.CYAN, "303": Fore.CYAN, "307": Fore.CYAN, "308": Fore.CYAN,
    "400": Fore.YELLOW, "401": Fore.YELLOW, "402": Fore.YELLOW, "403": Fore.YELLOW, "405": Fore.YELLOW, "444": Fore.YELLOW,
    "404": Fore.WHITE,
    "413": Fore.BLUE, "414": Fore.BLUE,
    "500": Fore.RED, "501": Fore.RED, "502": Fore.RED, "503": Fore.RED, "507": Fore.RED,
}

#
#### Request functions
#
async def make_aio_request( url, host=None, verb='GET', enum=None, trailing_slash=False, encode=False, user_agent=None, redirect=False, max_redirect = 0 ):
    final_url = ""
    try:
        if enum:
            if trailing_slash:
                full_url = f"{url.rstrip('/')}/{enum}"
            else:
                full_url = f"{url.rstrip('/')}{enum}"
        else:
            full_url = url
        parsed_url = urlparse(full_url)
        is_https = parsed_url.scheme == 'https'
        if encode:
            final_url = full_url
        else:
            final_url = URL(full_url, encoded=True)
        ssl_context = None
        if is_https:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        # Create Headers Object
        if user_agent:
            ua = user_agent
        else:
            ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36'
        headers = { 'User-Agent': ua }
        if host:
            headers['Host'] = host
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=4),
            max_field_size=65536,
            connector=aiohttp.TCPConnector(ssl=ssl_context) if is_https else None
        ) as session:
            try:
                async with session.request(
                    method=verb,
                    url=final_url,
                    headers=headers,
                    allow_redirects=redirect,
                    max_redirects=max_redirect
                ) as response:
                    body = await response.text()
                    return {
                        'status': str(response.status),
                        'headers': dict(response.headers),
                        'body': str(body),
                        'url': str(response.url)
                    }
            except aiohttp.ClientError as e:
                return { 'status': '0', 'headers': {}, 'body': '', 'url': final_url }
            except asyncio.TimeoutError as e:
                return { 'status': '0', 'headers': {}, 'body': '', 'url': final_url }
    except Exception as e:
        return { 'status': '0', 'headers': {}, 'body': '', 'url': final_url }

def make_requests_request( url, host=None, verb='GET', enum=None, trailing_slash=False, user_agent=None, redirect=False, max_redirect = 0 ):
    is_https = url.startswith('https')
    if enum:
        if trailing_slash:
            full_url = f"{url.rstrip('/')}/{enum}"
        else:
            full_url = f"{url.rstrip('/')}{enum}"
    else:
        full_url = url
    if user_agent:
        ua = user_agent
    else:
        ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36'
    headers = {'User-Agent': ua}
    if host:
        headers['Host'] = host
    try:
        response = requests.request(
            method=verb,
            url=full_url,
            headers=headers,
            allow_redirects=redirect,
            timeout=4,
            verify=False
        )

        return {
            'status': str(response.status_code),
            'headers': dict(response.headers),
            'body': str(response.text),
            'url': str(response.url)
        }
    except Exception as e:
        return { 'status': '0', 'headers': {}, 'body': '', 'url': full_url }

def make_requests_proto_request(url, host=None, verb='GET', enum=None, trailing_slash=False, user_agent=None, redirect=False, max_redirect=0, http_version='1.1'):
    is_https = url.startswith('https')
    if enum:
        full_url = f"{url.rstrip('/')}/{enum}" if trailing_slash else f"{url.rstrip('/')}{enum}"
    else:
        full_url = url
    ua = user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36'
    headers = {'User-Agent': ua}
    if host:
        headers['Host'] = host
    try:
        HTTPConnection._http_vsn_str = 'HTTP/' + http_version
        response = requests.request(
            method=verb,
            url=full_url,
            headers=headers,
            allow_redirects=redirect,
            timeout=4,
            verify=False
        )
        return {
            'status': str(response.status_code),
            'headers': dict(response.headers),
            'body': str(response.text),
            'url': str(response.url)
        }
    except Exception as e:
        return {'status': '0', 'headers': {}, 'body': '', 'url': full_url}
    finally:
        HTTPConnection._http_vsn_str = 'HTTP/1.1'

def make_raw_http_request(host, port, request_string, use_ssl=False):
    url = ""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, int(port)))

        if use_ssl:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            sock = ssl_context.wrap_socket(sock, server_hostname=host)

        # Send the raw HTTP request
        sock.send(request_string.encode())

        response = b""
        while True:
            data = sock.recv(1024)
            if not data:
                break
            response += data
        sock.close()
        response = response.decode()

        if use_ssl:
            url = f"https://{host}:{port}/"
        else:
            url = f"http://{host}:{port}/"
        
        # Parse the response into its parts
        lines = response.split('\r\n')

        # Pull status line
        status_line = lines[0]
        status_code = status_line.split(' ')[1]

        body_start = -1
        for i, line in enumerate(lines):
            if line == '':
                body_start = i + 1
                break
        
        # Get the headers
        headers = {}
        if body_start > 0:
            for line in lines[1:body_start-1]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
        
        body = '\r\n'.join(lines[body_start:]) if body_start > 0 else ''

        return {
            'status': str(status_code),
            'headers': dict(headers),
            'body': str(body),
            'url': str(url)
        }

        return response.decode()
    except Exception as e:
        return { 'status': '0', 'headers': {}, 'body': '', 'url': url }

#
#### Helper functions
#
def helpme():
    print ('\nWisQuas CLI 2026 :: Example usages...\n')
    print ("Use 'Desktop Browser' profile:")
    print ("./wisquas-cli.py -1 'https://www.example.com/'\n")

    print ("Use 'Mobile Browser' profile:")
    print ("./wisquas-cli.py -2 'https://www.example.com/'\n")

    print ("Use custom Host Header:")
    print ("./wisquas-cli.py -1 'https://www.example.com/' hostheader\n")
    sys.exit()

def print_baseline_status(url, host_ip, asnresponse_host):
    print(Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + "\nINITIALIZING WISQUAS SCANNER & ANOMALY DETECTOR...")
    print(Style.RESET_ALL + Fore.GREEN + Style.NORMAL + "Target URL: " + Fore.WHITE + Style.BRIGHT + url)
    print(Style.RESET_ALL + Fore.GREEN + Style.NORMAL + "Target IP:  "  + Fore.WHITE + Style.BRIGHT + host_ip,)
    try:
        print(Style.RESET_ALL + Fore.WHITE + Style.NORMAL)
        print(asnresponse_host.json()['org'])
        print(asnresponse_host.json()['city'], ",", asnresponse_host.json()['region'], ",", asnresponse_host.json()['country'], asnresponse_host.json()['postal'])
        print(asnresponse_host.json()['timezone'], "-", asnresponse_host.json()['loc'])
    except:
        print(Style.RESET_ALL + Fore.RED + Style.DIM + "[!] No ASN results to display")

def tld_extraction(url):
    if not url or not isinstance(url, str):
        return "", ""
    try:
        o = urlparse(url)
        if not o.netloc:
            o = urlparse("http://" + url)
        raw_host = o.hostname or ""
        if not raw_host:
            return url, url
        if raw_host == "localhost":
            return "localhost", "localhost"
        try:
            ipaddress.ip_address(raw_host)
            return raw_host, raw_host
        except ValueError:
            pass
        extracted = tldextract.extract(raw_host)
        if not extracted.domain or not extracted.suffix:
            return raw_host, raw_host
        domainname = extracted.domain + "." + extracted.suffix
        hosts = (extracted.subdomain + "." + domainname) if extracted.subdomain else domainname
        return hosts, domainname
    except Exception:
        return url, url

def print_baseline_req(baseline_req, url):
    all_cookies = baseline_req['headers'].get('Set-Cookie', [])
    all_headers = baseline_req['headers']
    responsecode = baseline_req['status']
    server = baseline_req['headers'].get('Server', '')
    responsecontentlen = len(baseline_req['body'])
    total_cookies = str(len(all_cookies))
    total_headers = str(len(all_headers))

    bshtml = bs4.BeautifulSoup(baseline_req['body'], features="html.parser")
    try:
        title = bshtml.title.text
        title = title.strip()
    except:
        pass
        title = ""
    try:
        location = baseline_req['headers'].get('Location', '')
        location = str(location)
    except:
        pass
        location = url
    try:
        https_soup = BeautifulSoup(baseline_req['body'],features="html.parser")
        https_td = https_soup.find('address')
        https_output = https_td.contents
        https_leak = https_output[0].strip()
    except:
        https_leak = ""
        pass
    print (Style.RESET_ALL)
    textcolor = status_color_map.get(responsecode, Fore.WHITE)
    
    print(textcolor + Style.NORMAL + "Original URL: " + Style.BRIGHT + url)
    print(Style.RESET_ALL + textcolor + Style.NORMAL + "Final Landing Page: " + Style.BRIGHT + location)
    print(Style.RESET_ALL + textcolor + Style.NORMAL + "Server: " + Style.BRIGHT + server)
    print(Style.RESET_ALL + textcolor + Style.NORMAL + "Title: " + Style.BRIGHT + title)
    print(Style.RESET_ALL + textcolor + Style.NORMAL + "Total Content-Length: " + Style.BRIGHT + str(responsecontentlen))
    print(Style.RESET_ALL + textcolor + Style.NORMAL + "Response Code: " + Style.BRIGHT + responsecode)
    print(Style.RESET_ALL + textcolor + Style.NORMAL + "Total Cookies: " + Style.BRIGHT + total_cookies)
    print(Style.RESET_ALL + textcolor + Style.NORMAL + "Total Headers: " + Style.BRIGHT + total_headers)
    print((Style.RESET_ALL + textcolor + Style.NORMAL + "VHOST Leakage: " + Style.BRIGHT + https_leak) + Style.RESET_ALL)

    print (Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + "\n\nALL DISCOVERED HTTP HEADERS:" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)
    for myheaders in all_headers:
        headersvalue = all_headers[myheaders]
        output2 = myheaders + " :: " + headersvalue
        print (output2)
        
    print ("\n")

def print_robots_text(robots_req):
    if robots_req['status'] == '200':
        print(Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + "DISCOVERED ROBOTS.TXT FILE OUTPUT:" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)
        print(robots_req['body'])
    else:
        print (Style.RESET_ALL + Fore.RED + Style.DIM + "[!] No ROBOTS.TXT file to display\n" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)

def print_sitemap_text(sitemap_xml_req):
    if sitemap_xml_req['status'] == '200':
        try:
            from lxml import etree
            xml = etree.fromstring(sitemap_xml_req['body'].encode())
            pretty = etree.tostring(xml, pretty_print=True).decode()
            print(Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + "DISCOVERED SITEMAP.XML FILE OUTPUT:" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)
            print(pretty)
        except:
            print (Style.RESET_ALL + Fore.RED + Style.DIM + "[!] SITEMAP.XML body is not XML\n" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)
    else:
        print (Style.RESET_ALL + Fore.RED + Style.DIM + "[!] No SITEMAP.XML file to display\n" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)

def print_manifest_json_text(manifest_json_req):
    if manifest_json_req['status'] == '200':
        try:
            manifest_json = json.loads(manifest_json_req['body'])
            print(Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + "DISCOVERED MANIFEST.JSON FILE OUTPUT:" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)
            print(json.dumps(manifest_json, indent=4))    
        except:
            print (Style.RESET_ALL + Fore.RED + Style.DIM + "[!] MANIFEST.JSON response is not JSON\n" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)            
    else:
        print (Style.RESET_ALL + Fore.RED + Style.DIM + "[!] No MANIFEST.JSON file to display\n" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)

def print_package_json_text(package_json_req):
    if package_json_req['status'] == '200':
        try:
            package_json = json.loads(package_json_req['body'])
            print(Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + "DISCOVERED PACKAGE.JSON FILE OUTPUT:" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)
            print(json.dumps(package_json, indent=4))    
        except:
            print (Style.RESET_ALL + Fore.RED + Style.DIM + "[!] PACKAGE.JSON response is not JSON\n" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)            
    else:
        print (Style.RESET_ALL + Fore.RED + Style.DIM + "[!] No PACKAGE.JSON file to display\n" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)

def print_server_status_links(server_status_req):
    if server_status_req['status'] == '200':
        try:
            links = []
            pattern = re.compile(r'nowrap>([^\s<]+)</td><td nowrap>(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT|LOCK|UNLOCK|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|BIND|UNBIND|REBIND|ACL|SEARCH|TRACK)\s+(\S+)\s+HTTP/[\d.]+')
            matches = pattern.findall(server_status_req['body'])
            if matches:
                for host, method, path in matches:
                    if not host or not path:
                        continue
                    links.append(f"{host}{path}")
            if len(links) > 0:
                print(Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + "DISCOVERED SERVER-STATUS LINKS OUTPUT:" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)
                for link in links:
                    print(link)
            else:
                print (Style.RESET_ALL + Fore.RED + Style.DIM + "[!] No server-status links to display\n" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)        
        except Exception as e:
            print (Style.RESET_ALL + Fore.RED + Style.DIM + "[!] Unknown server-status error\n" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)    
    else:
        print (Style.RESET_ALL + Fore.RED + Style.DIM + "[!] No server-status links to display\n" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)

def print_stats_1(url, host_ip, asnresponse_host):
    print(Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + "\nWISQUAS SCANNER SCAN RESULTS & STATS...")
    print(Style.RESET_ALL + Fore.GREEN + Style.NORMAL + "Target URL: " + Fore.WHITE + Style.BRIGHT + url)
    print(Style.RESET_ALL + Fore.GREEN + Style.NORMAL + "Target IP:  "  + Fore.WHITE + Style.BRIGHT + host_ip,)
    try:
        print(Style.RESET_ALL + Fore.WHITE + Style.NORMAL)
        print(asnresponse_host.json()['org'])
        print(asnresponse_host.json()['city'], ",", asnresponse_host.json()['region'], ",", asnresponse_host.json()['country'], asnresponse_host.json()['postal'])
        print(asnresponse_host.json()['timezone'], "-", asnresponse_host.json()['loc'])
    except:
        print(Style.RESET_ALL + Fore.RED + Style.DIM + "[!] No ASN results to display")

def print_stats_2(statobj, statobjname):
    print(Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + f"{str(statobjname)} STATS :: response_code / length / count:" + Style.RESET_ALL + Fore.GREEN + Style.NORMAL)
    for responsecode in sorted(statobj.keys()):
        try:
            sorted_lengths = sorted(statobj[responsecode].items(), key=lambda x: x[1]["count"], reverse=True)
            for length, data in sorted_lengths:
                textcolor = status_color_map.get(responsecode, Fore.WHITE)
                print(textcolor + str(responsecode) + " / " + str(length) + " / " + str(data['count']) + Style.RESET_ALL)
        except:
            pass
            
def print_stats_3(statobj, statobjname, name):
    if not statobj:
        print (Style.RESET_ALL + Fore.RED + Style.DIM + f"[!] No {str(statobjname)} STATS to display\n" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)        
        return
    valid_entries = {k: v for k, v in statobj.items() if k != "--"}
    if not valid_entries:
        print (Style.RESET_ALL + Fore.RED + Style.DIM + f"[!] No {str(statobjname)} STATS to display\n" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)        
        return
    print(Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + f"ALL OBSERVED {str(statobjname)} :: {str(name)} / count:" + Style.RESET_ALL + Fore.GREEN + Style.NORMAL)
    for key, data in sorted(statobj.items(), key=lambda x: x[1]["count"], reverse=True):
        if key != "--":
            print(str(key) + " / " + str(data['count']))

hosts_stats = {}
verbs_stats = {}
payloads_stats = {}

servers_stats = {}
title_stats = {}
address_stats = {}
locations_stats = {}
unique_redirect_stats = {}

def stat_counter(statobj, status, length):
    try:
        if status not in statobj:
            statobj[status] = {length: {"count": 1}}
        elif length in statobj[status]:
            statobj[status][length]["count"] += 1
        else:
            statobj[status][length] = {"count": 1}
    except:
        pass

def stat_counter2(obj, key):
    try:
        if key == "" or key == " ": # Handle blank values for the objects
            key = "--"
        if key not in obj:
            obj[key] = {"count": 1}
        else:
            obj[key]["count"] += 1
    except:
        pass

def wq_messages(reqobj, verb="", newhost="", enum="", proto=""):
    responsecode = str(reqobj['status'])
    responsecontent = (reqobj['body'])
    responseheaders = (reqobj['headers'])
    responsecookies = (reqobj['headers'].get('Set-Cookie', []))
    responsecontentlen = str(len(reqobj['body']))
    responseheaderslen = str(len(reqobj['headers']))
    responsecookieslen = str(len(reqobj['headers'].get('Set-Cookie', [])))
    server = reqobj['headers'].get('Server', '')

    stat_counter2(servers_stats, str(server))
    terminal_width = shutil.get_terminal_size().columns

    content_type = reqobj['headers'].get('Content-Type', '')
    xml_content_types = ('application/xml', 'text/xml', 'application/rss+xml', 'application/atom+xml')
    xml_filenames = ('sitemap.xml', 'web.config', 'feed.xml', 'atom.xml', 'rss.xml')

    is_xml = (
        any(ct in content_type for ct in xml_content_types) or
        (len(enum) > 0 and enum in xml_filenames)
    )

    if len(enum) > 0:
        parser = "xml" if is_xml else "html.parser"
        bshtml = bs4.BeautifulSoup(reqobj['body'], features=parser)
    else:
        bshtml = bs4.BeautifulSoup(reqobj['body'], features="html.parser")   

    try:
        title = bshtml.title.text
        title = title.strip()
    except:
        pass
        title = ""
    stat_counter2(title_stats, str(title))
    try:
        location = reqobj['headers'].get('Location', '')
        location = str(location)
        if len(location) > 69:
            location = location[:69]
    except:
        pass
        location = ""
    try:
        new_loc1, _ = tld_extraction(location)
        stat_counter2(unique_redirect_stats, str(new_loc1))
    except:
        pass
    try:
        https_soup = BeautifulSoup(reqobj['body'], features="xml" if is_xml else "html.parser")
        https_td = https_soup.find('address')
        https_output = https_td.contents
        https_leak = https_output[0].strip()
    except:
        https_leak = ""
        pass
    stat_counter2(address_stats, str(https_leak))
    textcolor = status_color_map.get(responsecode, Fore.WHITE)
    
    if len(verb) > 0:
        label = (verb + ":").ljust(32)
        print(textcolor + label + responsecode + " / " + responsecontentlen + " / " + responsecookieslen + " / " + responseheaderslen + " /  " + server + " /  " + title + " / " + https_leak + " / " + location + Style.RESET_ALL)
        stat_counter(verbs_stats, responsecode, responsecontentlen)
        stat_counter2(locations_stats, str(location))
        
    if len(newhost) > 0:
        label = (newhost + ":").ljust(32)
        print(textcolor + label + responsecode + " / " + responsecontentlen + " / " + responsecookieslen + " / " + responseheaderslen + " /  " + server + " /  " + title + " /  " + https_leak + " / " + location + Style.RESET_ALL)
        stat_counter(hosts_stats, responsecode, responsecontentlen)
        stat_counter2(locations_stats, str(location))
        
    if len(enum) > 0:
        if len(enum) > 100:
            enum = "FLOOD OVER 9K!"
        if enum == "/":
            enum = "//"
        if enum == "baseline":
            enum = "/"
        if enum == "<script>alert(1)</script>":
            enum = "<script>"
        
        if len(enum) > 32:
            label = (enum + ":").ljust(64)
        else:
            label = (enum + ":").ljust(32)
        print(textcolor + label + responsecode + " / " + responsecontentlen + " / " + responsecookieslen + " / " + responseheaderslen + " /  " + server + " /  " + title + " /  " + https_leak + " / " + location + Style.RESET_ALL)
        stat_counter(payloads_stats, responsecode, responsecontentlen)
    
    if len(proto) > 0:
        label = (proto + ":").ljust(32)
        print(textcolor + label + responsecode + " / " + responsecontentlen + " / " + responsecookieslen + " / " + responseheaderslen + " /  " + server + " /  " + title + " /  " + https_leak + " / " + location + Style.RESET_ALL)
        stat_counter2(locations_stats, str(location))

#
#### HTTP Verbs, Payloads, UAs
#
def wq_verbs(verb, url, hostheader, user_agent, baseline_req):
    if verb == 'GET':
        wq_messages(baseline_req, 'GET')
    else:
        try:
            if verb == 'CONNECT':
                response = make_requests_request(
                    f"{url}", hostheader, verb, '', False, user_agent
                ) # Requests library per how it handles the RFC
                wq_messages(response, verb)
            else:
                response = asyncio.run(
                    make_aio_request(
                        f"{url}", hostheader, verb, "", False, False, user_agent
                    )
                ) # AIO HTTP Request
                wq_messages(response, verb)
        except Exception as e:
            print(f"Ruh ruh... {e}")
            pass

def wq_hosts(host, url, user_agent):
    try:
        response = asyncio.run(
            make_aio_request( url, host, 'GET', "", False, False, user_agent )
        )
        wq_messages(response, "", str(host))
    except Exception as e:
        print(Style.RESET_ALL + Fore.RED + Style.DIM + newhost + ":\t\tAnomaly or Redirect Issue Detected!" + Style.RESET_ALL)

def wq_enum(
    enum, url, hostheader, user_agent, baseline_req, robots_req, sitemap_xml_req,
    manifest_json_req, package_json_req, server_status_req
):
    if enum == "baseline":
        wq_messages(baseline_req, "", "", "baseline")
    elif enum == "robots.txt":
        wq_messages(robots_req, "", "", "robots.txt")
    elif enum == "sitemap.xml":
        wq_messages(sitemap_xml_req, "", "", "sitemap.xml")
    elif enum == "manifest.json":
        wq_messages(manifest_json_req, "", "", "manifest.json")
    elif enum == "package.json":
        wq_messages(package_json_req, "", "", "package.json")
    elif enum == "server-status":
        wq_messages(server_status_req, "", "", "server-status")
    else:
        try:
            response = asyncio.run(
                make_aio_request(
                    f"{url}", hostheader, 'GET', enum, True, False, user_agent
                )
            )
            wq_messages(response, "", "", enum)
        except:
            print("Ruh roh...")

def wq_protos(proto, url, user_agent, host_header):
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == 'https' else 80)
        scheme = parsed.scheme
        
        original_resp = make_requests_proto_request(url, host_header, 'GET', None, False, user_agent, False, 0, str(proto))
        request_raw_string = 'GET / HTTP/' + proto + '\r\n\r\n'
        if parsed.scheme == 'https':
            response = make_raw_http_request(host, port, request_raw_string, use_ssl=True)
        elif parsed.scheme == 'http':
            response = make_raw_http_request(host, port, request_raw_string, use_ssl=False)
        else:
            response = make_raw_http_request(host, port, request_raw_string, use_ssl=False)
        
        wq_messages(original_resp, "", "", "", f"NORMAL HTTP/{proto}")
        wq_messages(response, "", "", "", f"SOCKET HTTP/{proto}")
        print()
        
    except Exception as e:
        print(Style.RESET_ALL + Fore.RED + Style.DIM + host + ":\t\tProtoscan Issue Detected!" + Style.RESET_ALL)

#
#### Main Logic
#
def wisquas_cli_main():
    try: # Parse URL
        url = sys.argv[2]
    except:
        helpme()
    
    # Parse the agent
    agent = sys.argv[1]
    if agent not in ["-1","-2"]:
        helpme()

    try: # Parse host header
        custom_host_header = sys.argv[3]
    except:
        pass
        custom_host_header = " "

    try: # Parse user agent
        if agent == "-1":
            user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36'
            print(Fore.GREEN + Style.DIM + " [X] Using 'Desktop Browser' user-agent" + Style.RESET_ALL)
            print()
        else:
            user_agent = 'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.118 Mobile Safari/537.36'
            print(Fore.GREEN + Style.DIM + "[X] Using 'Mobile Browser' user-agent" + Style.RESET_ALL)
            print()
    except:
        user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36'
        print(Fore.GREEN + Style.DIM + " [X] Using 'Desktop Browser' user-agent" + Style.RESET_ALL)
        print()
        pass

    hosts, domainname = tld_extraction(url)
    if custom_host_header != " ":
        hostheader = custom_host_header
    else:
        hostheader = hosts

    #######    ASN LOOKUP   ###############################################
    try:
        host_ip = socket.gethostbyname(hosts)
    except:
        host_ip = domainname

    try:
        ip_obj = ipaddress.ip_address(host_ip)
        if ip_obj.is_loopback or ip_obj.is_private:
            asnresponse_host = ""
        else:
            asnresponse_host = requests.get('http://ipinfo.io/' + host_ip, allow_redirects=False)
            asnresponse_host.json()
    except ValueError:
        try:
            asnresponse_host = requests.get('http://ipinfo.io/' + host_ip, allow_redirects=False)
            asnresponse_host.json()
        except:
            asnresponse_host = ""
    except:
        asnresponse_host = ""

    #######    Baseline Stuffs   ###############################################
    print_baseline_status(url, host_ip, asnresponse_host)
    try:
        baseline_req = asyncio.run(
            make_aio_request( url, hostheader, 'GET', None, False, False, user_agent )
        )
        print_baseline_req(baseline_req, url)
    except:
        print("Unknown baseline error!")
        baseline_req = {}
        pass

    #######    Robots.txt   ###############################################
    try:
        robots_req = asyncio.run(
            make_aio_request( f"{url}", hostheader, 'GET', 'robots.txt', True, False, user_agent )
        )
    except:
        robots_req = {}
        print("Unknown robots.txt request error!")

    #######    Sitemap.xml   ###############################################
    try:
        sitemap_xml_req = asyncio.run(
            make_aio_request( f"{url}", hostheader, 'GET', 'sitemap.xml', True, False, user_agent )
        )
    except:
        sitemap_xml_req = {}
        print("Unknown sitemap.xml request error!")

    #######    Manifest.json   ###############################################
    try:
        manifest_json_req = asyncio.run(
            make_aio_request( f"{url}", hostheader, 'GET', 'manifest.json', True, False, user_agent )
        )
    except:
        manifest_json_req = {}
        print("Unknown manifest.json request error!")

    #######    package.json   ###############################################
    try:
        package_json_req = asyncio.run(
            make_aio_request( f"{url}", hostheader, 'GET', 'package.json', True, False, user_agent )
        )
    except:
        package_json_req = {}
        print("Unknown package.json request error!")

    #######    server-status   ###############################################
    try:
        server_status_req = asyncio.run(
            make_aio_request( f"{url}", hostheader, 'GET', 'server-status', True, False, user_agent )
        )
    except:
        server_status_req = {}
        print("Unknown server-status request error!")
    
    #######    HTTP PAYLOADS ENUMERATIONS   ###############################################
    print()
    print(Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + "ENUMERATING PAYLOADS :: response_code / length / cookies / headers / server / title / vhost_leak / location:" + Style.RESET_ALL + Fore.GREEN + Style.NORMAL)
    wq_enum("baseline", url, hostheader, user_agent, baseline_req, {}, {}, {}, {}, {})
    for enum in enum_payloads:
        if enum == "robots.txt":
            wq_enum(enum, url, hostheader, user_agent, {}, robots_req, {}, {}, {}, {})
        elif enum == "sitemap.xml":
            wq_enum(enum, url, hostheader, user_agent, {}, {}, sitemap_xml_req, {}, {}, {})
        elif enum == "manifest.json":
            wq_enum(enum, url, hostheader, user_agent, {}, {}, {}, manifest_json_req, {}, {})
        elif enum == "package.json":
            wq_enum(enum, url, hostheader, user_agent, {}, {}, {}, {}, package_json_req, {})
        elif enum == "server-status":
            wq_enum(enum, url, hostheader, user_agent, {}, {}, {}, {}, {}, server_status_req)
        else:
            wq_enum(enum, url, hostheader, user_agent, {}, {}, {}, {}, {}, {})

    #######    HTTP VERBS   ###############################################
    print()
    print (Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + "\nHTTP VERB ENUMERATIONS :: response_code / length / cookies / headers / server / title / vhost_leak / location:" + Style.RESET_ALL + Fore.GREEN + Style.NORMAL)
    for verb in verbs:
        if verb == 'GET':
            wq_verbs(verb, url, hostheader, user_agent, baseline_req)
        else:
            wq_verbs(verb, url, hostheader, user_agent, {})

    #######    HTTP HOSTS ENUMERATIONS   ###############################################
    print()
    print (Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + "\n\nHTTP HOST HEADER ENUMERATIONS :: response_code / length / cookies / headers / server / title / vhost_leak / location:" + Style.RESET_ALL + Fore.GREEN + Style.NORMAL)
    wq_hosts(hosts, url, user_agent)
    for h in enum_hosts:
        wq_hosts(h, url, user_agent)
    
    #######    Protoscan   ###############################################
    print()
    print (Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + "\n\nRUNNING PROTOCOL SCANNER :: response_code / length / cookies / headers / server / title / vhost_leak / location:" + Style.RESET_ALL + Fore.GREEN + Style.NORMAL)
    for proto in protos:
        wq_protos(proto, url, user_agent, hostheader)

    #######    Allurls   ###############################################
    print()
    print_robots_text(robots_req)
    print()
    print_sitemap_text(sitemap_xml_req)

    #######    Po-mans heartbleed (server-status)   ###############################################
    print()
    print_server_status_links(server_status_req)

    #######    Manifests and packages/SBOM   ###############################################
    print()
    print_manifest_json_text(manifest_json_req)
    print()
    print_package_json_text(package_json_req)

    #######    Stat Boxes   ###############################################
    print()
    print_stats_1(url, host_ip, asnresponse_host)
    print()
    print_stats_2(payloads_stats, "PAYLOADS") # Payloads
    print()
    print_stats_2(verbs_stats, "VERBS") # Verbs
    print()
    print_stats_2(hosts_stats, "HOSTS") # Hosts
    print()
    print_stats_3(servers_stats, "SERVERS", "server_name") # Servers
    print()
    print_stats_3(title_stats, "TITLES", "title") # Titles
    print()
    print_stats_3(address_stats, "ADDRESS HTML TAGS", "address") # Addresses
    print()
    print_stats_3(locations_stats, "LOCATIONS", "redirect_location") # Locations
    print()
    print_stats_3(unique_redirect_stats, "UNIQUE REDIRECT HOSTS", "redirect_host") # Unique redirect hosts
    
    print (Style.RESET_ALL + Fore.GREEN + Style.BRIGHT + "\n🐇🐇🐇🐇🐇 WISQUAS SCAN COMPLETE :: More info at https://gitlab.com/LostRabbitLabs 🐇🐇🐇🐇🐇\n" + Style.RESET_ALL)

if __name__ == "__main__":
    wisquas_cli_main()