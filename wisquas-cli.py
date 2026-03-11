#!/usr/bin/python3
import aiohttp # type: ignore
import asyncio # type: ignore
import bs4 # type: ignore
import hashlib # type: ignore
import ipaddress # type: ignore
import json # type: ignore
import re # type: ignore
import requests # type: ignore
import shutil # type: ignore
import socket # type: ignore
import sourcemap # type: ignore
import ssl # type: ignore
import sys # type: ignore
import time # type: ignore
import tldextract # type: ignore
import urllib.parse # type: ignore
import urllib3 # type: ignore
import warnings # type: ignore

from bs4 import BeautifulSoup # type: ignore
from bs4 import MarkupResemblesLocatorWarning # type: ignore
from bs4 import XMLParsedAsHTMLWarning # type: ignore
from colorama import Fore, Style # type: ignore
from http.client import HTTPConnection # type: ignore
from lxml import etree # type: ignore
from pathlib import Path # type: ignore
from requests.adapters import HTTPAdapter # type: ignore
from urllib.parse import urljoin, urlparse # type: ignore
from urllib3.util.ssl_ import create_urllib3_context # type: ignore
from yarl import URL # type: ignore

# Script Configuration
WQ_PROXY=""
# WQ_PROXY="http://127.0.0.1:8080"

enum_payloads = [
    "/",
    "%2f",
    "%2f%2f",
    "%2e",
    "%2e%2e",
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
    "home",
    "en_us",
    "en_us/",
    "us",
    "us/",
    "favicon.ico",
    "robots.txt",
    "sitemap.xml",
    "crossdomain.xml",
    "clientaccesspolicy.xml",
    ".well-known/",
    ".env",
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
    "config.xml",
    "login.php",
    "app.js",
    "worker.js",
    "bundle.js",
    "config.js",
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
    "?url=",
    "?q=1' or '1'='1",
    r'?\[',
    "swagger.json",
    "openapi.json",
    "api/",
    "api",
    "api/users",
    "api/v1/",
    "api/v2/",
    "api/status",
    "api/health",
    "rest/config",
    "rest/admin",
    "metrics",
    "actuator",
    "webhooks",
    "<script>alert(1)</script>",
    "z'%3balert(1)%2f%2f157",
    "cgi-bin",
    "webmail",
    "nginx_status",
    "redirect",
    "{",
    "}",
    "%7b",
    "`",
    "'or '1'='1",
    "~",
    ",",
    "&",
    "%",
    "%%",
    "%00",
    "%c0",
    "%p",
    "%20X",
    "%20H",
    "configuration.yaml",
    "configuration.json",
    "package.json",
    "manifest.json",
    "elmah.axd",
    "public/",
    "_vti_pvt/service.cnf",
    "login?next=/",
    "WS_FTP.LOG",
    "login.asp.bak",
    "graphql",
    "../../../etc/passwd",
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

# Warning Supression
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", "ssl.wrap_socket", DeprecationWarning)
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

#
#### HTTP Request Functions
#
def make_chrome_ssl_context(): # Spoofs JA3 and JA4 hashes for chrome browser via aiohttp
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers( # Chrome browser's default ciphers
        "TLS_AES_128_GCM_SHA256:" "TLS_AES_256_GCM_SHA384:" "TLS_CHACHA20_POLY1305_SHA256:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:" "ECDHE-RSA-AES128-GCM-SHA256:" "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:" "ECDHE-ECDSA-CHACHA20-POLY1305:" "ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-AES128-SHA:" "ECDHE-RSA-AES256-SHA:" "AES128-GCM-SHA256:" "AES256-GCM-SHA384:"
        "AES128-SHA:" "AES256-SHA"
    )
    ctx.set_alpn_protocols(["http/1.1"])
    try:
        ctx.set_ecdh_curve("prime256v1")
    except Exception as e:
        pass
    return ctx

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
            ssl_context = make_chrome_ssl_context()
        # Create Headers Object
        if user_agent:
            ua = user_agent
        else:
            ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36'
        headers = {
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': ua,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
        }
        if host:
            headers['Host'] = host
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            max_field_size=65536,
            connector=aiohttp.TCPConnector(ssl=ssl_context) if is_https else None
        ) as session:
            try:
                if WQ_PROXY:
                    async with session.request(
                        method=verb,
                        url=final_url,
                        headers=headers,
                        allow_redirects=redirect,
                        max_redirects=max_redirect,
                        proxy=WQ_PROXY
                    ) as response:
                        body = await response.text()
                        return {
                            'status': str(response.status),
                            'headers': dict(response.headers),
                            'body': str(body),
                            'url': str(response.url)
                        }
                else:
                    async with session.request(
                        method=verb,
                        url=final_url,
                        headers=headers,
                        allow_redirects=redirect,
                        max_redirects=max_redirect
                    ) as response:
                        rawbody = await response.read()
                        try:
                            body = rawbody.decode(response.charset or 'utf-8', errors='replace')
                        except (LookupError, TypeError):
                            body = rawbody.decode('utf-8', errors='replace')
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
    headers = {
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': ua,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
    }
    if host:
        headers['Host'] = host
    try:
        session = requests.Session()
        if is_https:
            class _SSLAdapter(HTTPAdapter):
                def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
                    pool_kwargs["ssl_context"] = make_chrome_ssl_context()
                    super().init_poolmanager(connections, maxsize, block, **pool_kwargs)
            session.mount("https://", _SSLAdapter())
        response = session.request(
            method=verb,
            url=full_url,
            headers=headers,
            allow_redirects=redirect,
            timeout=10,
            verify=False,
            proxies={"http": WQ_PROXY, "https": WQ_PROXY} if WQ_PROXY else None
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
    headers = {
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': ua,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
    }
    if host:
        headers['Host'] = host
    try:
        HTTPConnection._http_vsn_str = 'HTTP/' + http_version
        response = requests.request(
            method=verb,
            url=full_url,
            headers=headers,
            allow_redirects=redirect,
            timeout=10,
            verify=False,
            proxies={"http": WQ_PROXY, "https": WQ_PROXY} if WQ_PROXY else None
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
#### Message/Print Statement Helper Functions
#
def helpme():
    print('\nWisQuas CLI 2026 :: Example usages...\n')
    print("Use 'Desktop Browser' profile:")
    print("./wisquas-cli.py -1 'https://www.example.com/'\n")
    print("Use 'Mobile Browser' profile:")
    print("./wisquas-cli.py -2 'https://www.example.com/'\n")
    print("Use custom Host Header:")
    print("./wisquas-cli.py -1 'https://www.example.com/' hostheader\n")
    sys.exit()

def printcl(s):
    print(s.replace('\n', ' ').replace('\r', ' '))

def print_baseline_status(url, host_ip, asnresponse_host):
    print(Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + "\nINITIALIZING WISQUAS SCANNER & ANOMALY DETECTOR...")
    print(Style.RESET_ALL + Fore.GREEN + Style.NORMAL + "Target URL: " + Fore.WHITE + Style.BRIGHT + url)
    print(Style.RESET_ALL + Fore.GREEN + Style.NORMAL + "Target IP:  "  + Fore.WHITE + Style.BRIGHT + host_ip)
    try:
        print(Style.RESET_ALL + Fore.WHITE + Style.NORMAL)
        print(asnresponse_host.json()['org'])
        print(asnresponse_host.json()['city'], ",", asnresponse_host.json()['region'], ",", asnresponse_host.json()['country'], asnresponse_host.json()['postal'])
        print(asnresponse_host.json()['timezone'], "-", asnresponse_host.json()['loc'])
    except:
        print(Style.RESET_ALL + Fore.RED + Style.DIM + "[!] No ASN results to display")

def print_baseline_req(baseline_req, url):
    all_cookies = baseline_req['headers'].get('Set-Cookie', [])
    all_headers = baseline_req['headers']
    responsecode = baseline_req['status']
    server = baseline_req['headers'].get('Server', '--')
    responsecontentlen = len(baseline_req['body'])
    total_cookies = str(len(all_cookies))
    total_headers = str(len(all_headers))

    bshtml = bs4.BeautifulSoup(baseline_req['body'], features="html.parser")
    try:
        title = bshtml.title.text
        title = title.strip()
        if len(title) == 0:
            title = "--"
    except:
        title = "--"
    try:
        location = baseline_req['headers'].get('Location', '--')
        location = str(location)
    except:
        location = url
    try:
        https_soup = BeautifulSoup(baseline_req['body'],features="html.parser")
        https_td = https_soup.find('address')
        https_output = https_td.contents
        https_leak = https_output[0].strip()
        if len(https_leak) == 0:
            https_leak = "--"
    except:
        https_leak = "--"
    print(Style.RESET_ALL)
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

    print(Style.RESET_ALL + textcolor + Style.NORMAL + "\n\nALL DISCOVERED HTTP HEADERS: " + Style.BRIGHT + total_headers)
    for myheaders in all_headers:
        headersvalue = all_headers[myheaders]
        output2 = myheaders + " :: " + headersvalue
        print(Style.RESET_ALL + textcolor + Style.BRIGHT + output2 + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)
    print("\n")

def print_robots_text(robots_req, all_urls, third_party_urls, url, main_output_dir):
    if robots_req['status'] == '200':
        print(Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + "DISCOVERED ROBOTS.TXT FILE OUTPUT:" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)
        print(robots_req['body'])
        try:
            try:
                _, base_domain = tld_extraction(url)
            except Exception as e:
                return all_urls, third_party_urls
            try:
                base_scheme = urlparse(url).scheme or "https"
            except Exception as e:
                base_scheme = "https"
            urls = []
            thirdparty = []
            for line in robots_req['body'].splitlines():
                try:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" not in line:
                        continue
                    directive, _, value = line.partition(":")
                    directive = directive.strip().lower()
                    value = value.strip()
                    if not value:
                        continue
                    if directive in ("sitemap", "allow", "disallow"):
                        if value.startswith("//"):
                            value = base_scheme + ":" + value
                        u = urljoin(url, value) if url else value
                        if not u:
                            continue
                        try:
                            _, u_domain = tld_extraction(u)
                            if u_domain == base_domain and u not in urls:
                                urls.append(str(u))
                            else:
                                if u not in thirdparty:
                                    thirdparty.append(str(u))
                        except Exception as e:
                            pass
                except Exception as e:
                    pass
            all_urls = write_urls_file(urls, all_urls, f"{main_output_dir}/allurls.txt")
            third_party_urls = write_urls_file(thirdparty, third_party_urls, f"{main_output_dir}/3rdpartyurls.txt")
        except Exception as e:
            pass
    else:
        print(Style.RESET_ALL + Fore.RED + Style.DIM + "[!] No ROBOTS.TXT file to display\n" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)
    return all_urls, third_party_urls

def print_sitemap_text(sitemap_xml_req, all_urls, third_party_urls, url, main_output_dir):
    if sitemap_xml_req['status'] == '200':
        try:
            xml = etree.fromstring(sitemap_xml_req['body'].encode())
            pretty = etree.tostring(xml, pretty_print=True).decode()
            print(Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + "DISCOVERED SITEMAP.XML FILE OUTPUT:" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)
            print(pretty)
            try:
                found_urls = []
                found_3rd_party_urls = []
                try:
                    _, base_domain = tld_extraction(url)
                except Exception as e:
                    pass
                for line in sitemap_xml_req['body'].splitlines():
                    for u in re.findall(r'https?://[^<"\s]+', line):
                        if "sitemaps.org" in u:
                            continue
                        if "google.com/schemas/sitemap" in u:
                            continue
                        try:
                            _, u_domain = tld_extraction(u)
                            if u_domain == base_domain:
                                if u not in found_urls:
                                    found_urls.append(u)
                            else:
                                if u not in found_3rd_party_urls:
                                    found_3rd_party_urls.append(u)
                        except Exception as e:
                            pass
                all_urls = write_urls_file(found_urls, all_urls, f"{main_output_dir}/allurls.txt")
                third_party_urls = write_urls_file(found_3rd_party_urls, third_party_urls, f"{main_output_dir}/3rdpartyurls.txt")
            except Exception as e:
                pass
        except:
            print(Style.RESET_ALL + Fore.RED + Style.DIM + "[!] SITEMAP.XML body is not XML\n" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)
    else:
        print(Style.RESET_ALL + Fore.RED + Style.DIM + "[!] No SITEMAP.XML file to display\n" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)
    return all_urls, third_party_urls

def print_manifest_json_text(manifest_json_req):
    if manifest_json_req['status'] == '200':
        try:
            manifest_json = json.loads(manifest_json_req['body'])
            print(Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + "DISCOVERED MANIFEST.JSON FILE OUTPUT:" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)
            print(json.dumps(manifest_json, indent=4))    
        except:
            print(Style.RESET_ALL + Fore.RED + Style.DIM + "[!] MANIFEST.JSON response is not JSON\n" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)            
    else:
        print(Style.RESET_ALL + Fore.RED + Style.DIM + "[!] No MANIFEST.JSON file to display\n" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)

def print_package_json_text(package_json_req):
    if package_json_req['status'] == '200':
        try:
            package_json = json.loads(package_json_req['body'])
            print(Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + "DISCOVERED PACKAGE.JSON FILE OUTPUT:" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)
            print(json.dumps(package_json, indent=4))    
        except:
            print(Style.RESET_ALL + Fore.RED + Style.DIM + "[!] PACKAGE.JSON response is not JSON\n" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)            
    else:
        print(Style.RESET_ALL + Fore.RED + Style.DIM + "[!] No PACKAGE.JSON file to display\n" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)

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
                    if f"{host}{path}" not in links:
                        links.append(f"{host}{path}")
            if len(links) > 0:
                print(Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + "DISCOVERED SERVER-STATUS LINKS OUTPUT:" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)
                for link in links:
                    print(link)
                    with open("server-status-links.txt", "a") as f:
                        f.write(f"{str(link)}\n")
            else:
                print(Style.RESET_ALL + Fore.RED + Style.DIM + "[!] No server-status links to display\n" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)        
        except Exception as e:
            print(Style.RESET_ALL + Fore.RED + Style.DIM + "[!] Unknown server-status error\n" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)    
    else:
        print(Style.RESET_ALL + Fore.RED + Style.DIM + "[!] No server-status links to display\n" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)

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
        print(Style.RESET_ALL + Fore.RED + Style.DIM + f"[!] No {str(statobjname)} STATS to display\n" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)        
        return
    valid_entries = {k: v for k, v in statobj.items() if k != "--"}
    if not valid_entries:
        print(Style.RESET_ALL + Fore.RED + Style.DIM + f"[!] No {str(statobjname)} STATS to display\n" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)        
        return
    print(Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + f"ALL OBSERVED {str(statobjname)} :: {str(name)} / count:" + Style.RESET_ALL + Fore.GREEN + Style.NORMAL)
    for key, data in sorted(statobj.items(), key=lambda x: x[1]["count"], reverse=True):
        if key != "--":
            print(str(key) + " :: " + str(data['count']))

#
#### Data Processing/Parser Helper Functions
#
hosts_stats = {}
verbs_stats = {}
payloads_stats = {}

servers_stats = {}
title_stats = {}
address_stats = {}
locations_stats = {}
unique_redirect_stats = {}

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

def wq_messages(main_output_dir, reqobj, all_urls, third_party_urls, url, verb="", newhost="", enum="", proto="", jsfile=""):
    responsecode = str(reqobj['status'])
    responsecontent = (reqobj['body'])
    responseheaders = (reqobj['headers'])
    responsecookies = (reqobj['headers'].get('Set-Cookie', []))
    responsecontentlen = str(len(reqobj['body']))
    responseheaderslen = str(len(reqobj['headers']))
    responsecookieslen = str(len(reqobj['headers'].get('Set-Cookie', [])))
    server = reqobj['headers'].get('Server', '--')

    try: # Record observed body URLs
        if responsecode not in ("301", "302", "303", "307", "308"):
            general_baseline_urls, third_party_baseline_urls = baseline_url_parser(
                str(responsecontent),
                str(url[:-1] if url.endswith("/") else url)
            )
            all_urls = write_urls_file(general_baseline_urls, all_urls, f"{main_output_dir}/allurls.txt")
            third_party_urls = write_urls_file(third_party_baseline_urls, third_party_urls, f"{main_output_dir}/3rdpartyurls.txt")
    except:
        pass

    try: # Record observed header URLs
        general_baseline_urls2, third_party_baseline_urls2 = headers_url_parser(responseheaders, url)
        all_urls = write_urls_file(general_baseline_urls2, all_urls, f"{main_output_dir}/allurls.txt")
        third_party_urls = write_urls_file(third_party_baseline_urls2, third_party_urls, f"{main_output_dir}/3rdpartyurls.txt")
    except Exception as e:
        pass

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
        if len(title) == 0:
            title = "--"    
    except:
        title = "--"
    stat_counter2(title_stats, str(title))
    try:
        location = reqobj['headers'].get('Location', '')
        location = str(location)
        if len(location) > 69:
            location = location[:69]
        if len(location) == 0:
            location = "--"
    except:
        location = "--"
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
        if len(https_leak) == 0:
            https_leak = "--"    
    except:
        https_leak = "--"
    stat_counter2(address_stats, str(https_leak))
    textcolor = status_color_map.get(responsecode, Fore.WHITE)

    image_sum = "" # MD5 Sum of image file detected
    if any(content_type.startswith(t) for t in ('image/', 'application/x-ico', 'application/ico')):
        if len(responsecontent) > 0:
            try:
                image_sum = str(hashlib.md5(responsecontent.encode()).hexdigest())
            except:
                pass
    
    if len(verb) > 0:
        label = (verb + ":").ljust(32)
        if len(image_sum) > 0:
            printcl(textcolor + label + responsecode + " / " + responsecontentlen + " / " + responsecookieslen + " / " + responseheaderslen + " / " + server + " / " + title + " / " + https_leak + " / " + location + " / " + "[MD5:" + str(image_sum) + "]" + Style.RESET_ALL)
        else:
            printcl(textcolor + label + responsecode + " / " + responsecontentlen + " / " + responsecookieslen + " / " + responseheaderslen + " / " + server + " / " + title + " / " + https_leak + " / " + location + Style.RESET_ALL)
        stat_counter(verbs_stats, responsecode, responsecontentlen)
        stat_counter2(locations_stats, str(location))
        
    if len(newhost) > 0:
        label = (newhost + ":").ljust(32)
        if len(image_sum) > 0:
            printcl(textcolor + label + responsecode + " / " + responsecontentlen + " / " + responsecookieslen + " / " + responseheaderslen + " / " + server + " / " + title + " / " + https_leak + " / " + location + " / " + "[MD5:" + str(image_sum) + "]" + Style.RESET_ALL)
        else:
            printcl(textcolor + label + responsecode + " / " + responsecontentlen + " / " + responsecookieslen + " / " + responseheaderslen + " / " + server + " / " + title + " / " + https_leak + " / " + location + Style.RESET_ALL)
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
        if len(image_sum) > 0:
            printcl(textcolor + label + responsecode + " / " + responsecontentlen + " / " + responsecookieslen + " / " + responseheaderslen + " / " + server + " / " + title + " / " + https_leak + " / " + location + " / " + "[MD5:" + str(image_sum) + "]" + Style.RESET_ALL)
        else:
            printcl(textcolor + label + responsecode + " / " + responsecontentlen + " / " + responsecookieslen + " / " + responseheaderslen + " / " + server + " / " + title + " / " + https_leak + " / " + location + Style.RESET_ALL)
        stat_counter(payloads_stats, responsecode, responsecontentlen)
    
    if len(proto) > 0:
        label = (proto + ":").ljust(32)
        if len(image_sum) > 0:
            printcl(textcolor + label + responsecode + " / " + responsecontentlen + " / " + responsecookieslen + " / " + responseheaderslen + " / " + server + " / " + title + " / " + https_leak + " / " + location + " / " + "[MD5:" + str(image_sum) + "]" + Style.RESET_ALL)
        else:
            printcl(textcolor + label + responsecode + " / " + responsecontentlen + " / " + responsecookieslen + " / " + responseheaderslen + " / " + server + " / " + title + " / " + https_leak + " / " + location + Style.RESET_ALL)
        stat_counter2(locations_stats, str(location))

    return all_urls, third_party_urls

#
#### Secondary Parsers/Processors
#
TAG_URL_ATTRIBUTES = {
    "a":        ["href"], "applet":   ["code"], "area":     ["href"],
    "audio":    ["src", "poster"], "bgsound":  ["src"], "body":     ["background"],
    "embed":    ["href", "src"], "fig":      ["src"], "frame":    ["src"],
    "iframe":   ["src"], "img":      ["href", "lowsrc", "src", "srcset"],
    "input":    ["src"], "layer":    ["src"], "link":     ["href"],
    "object":   ["data"], "overlay":  ["src"], "script":   ["src"],
    "source":   ["src", "srcset"], "table":    ["background"], "td":       ["background"],
    "th":       ["background"], "video":    ["src", "poster"]
}
CSS_URL_RE = re.compile(r'url\(\s*["\']?([^)"\']+)["\']?\s*\)', re.IGNORECASE)
def baseline_url_parser(html, base_url=""):
    try:
        warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
        soup = BeautifulSoup(html, "html.parser")
    except Exception as e:
        return []
    urls = []
    for tag, attrs in TAG_URL_ATTRIBUTES.items():
        for el in soup.find_all(tag):
            for attr in attrs:
                try:
                    val = el.get(attr)
                    if not val:
                        continue
                    if attr == "srcset":
                        urls += [e.strip().split()[0] for e in val.split(",") if e.strip()]
                    else:
                        urls.append(val)
                except Exception as e:
                    pass
    for el in soup.find_all(True):
        try:
            if el.get("style"):
                urls += CSS_URL_RE.findall(el["style"])
        except Exception as e:
            pass
    for el in soup.find_all("style"):
        try:
            if el.string:
                urls += CSS_URL_RE.findall(el.string)
        except Exception as e:
            pass
    for el in soup.find_all("meta", attrs={"http-equiv": re.compile("refresh", re.I)}):
        try:
            m = re.search(r'URL=(.+)', el.get("content", ""), re.I)
            if m:
                urls.append(m.group(1).strip())
        except Exception as e:
            pass
    resolved = []
    try:
        base_scheme = urlparse(base_url).scheme or "https"
    except Exception as e:
        base_scheme = "https"
    for u in urls:
        try:
            if not u or u.startswith("data:"):
                continue
            if u.startswith("//"):
                u = base_scheme + ":" + u
            u = urljoin(base_url, u) if base_url else u
            scheme = urlparse(u).scheme.lower()
            if scheme not in ("http", "https"):
                continue
            if urlparse(u).path == "":
                u = u.replace("?", "/?").replace("#", "/#") if "?" in u or "#" in u else u + "/"
            resolved.append(u)
        except Exception as e:
            pass
    
    try:
        _, base_domain = tld_extraction(base_url)
    except Exception as e:
        return [], [] # Handle cases for malformed URLs
    general = []
    thirdparty = []
    for u in resolved:
        try:
            _, u_domain = tld_extraction(u)
            if u_domain == base_domain:
                if u not in general:
                    general.append(u)
            else:
                if u not in thirdparty:
                    thirdparty.append(u)
        except Exception as e:
            pass
    return general, thirdparty

def write_urls_file(urls, dup_arr, file_name):
    try:
        with open(file_name, "a") as f:
            for u in urls:
                try:
                    if u not in dup_arr:
                        f.write(f"{str(u)}\n")
                        dup_arr.append(u)    
                except Exception as e:
                    pass
            return dup_arr
    except Exception as e:
        return dup_arr

def final_sort_urls_files(file_name):
    with open(file_name, "r") as f:
        l = f.readlines()
    l = sorted(set(l))
    with open(file_name, "w") as f:
        f.writelines(l)

def headers_url_parser(hdict, url):
    def validate_url(u, found_urls, found_3rd_party_urls): # Looser 
        try:
            for v in re.findall(r'https?://[^;<>\s]+', u):
                try:
                    _, u_domain = tld_extraction(v)
                    if u_domain == base_domain:
                        if v not in found_urls:
                            found_urls.append(v)
                    else:
                        if v not in found_3rd_party_urls:
                            found_3rd_party_urls.append(v)
                except:
                    continue
        except:
            pass
        return found_urls, found_3rd_party_urls
    
    def print_json(obj, found_urls, found_3rd_party_urls):
        if isinstance(obj, dict):
            for key, value in obj.items():
                found_urls, found_3rd_party_urls = validate_url(key, found_urls, found_3rd_party_urls)
                if not isinstance(value, (dict, list)):
                    found_urls, found_3rd_party_urls = validate_url(value, found_urls, found_3rd_party_urls)
                print_json(value, found_urls, found_3rd_party_urls)
        elif isinstance(obj, list):
            for item in obj:
                print_json(item, found_urls, found_3rd_party_urls)
        return found_urls, found_3rd_party_urls
    
    try:
        found_urls = []
        found_3rd_party_urls = []
        try:
            _, base_domain = tld_extraction(url)
        except Exception as e:
            pass
        for h, v in hdict.items():
            try:
                if h.lower() == "location":
                    continue
                success = False
                try: # Try to load JSON header data
                    j = json.loads(v)
                    print_json(j, found_urls, found_3rd_party_urls)
                    success = True
                except Exception as e:
                    pass

                try: # Match on blob using a stricter matcher
                    if not success:
                        for u in re.findall(r'https?://[^<>"\';\s}]+', v):
                            try:
                                _, u_domain = tld_extraction(u)
                                if u_domain == base_domain:
                                    if u not in found_urls:
                                        found_urls.append(u)
                                else:
                                    if u not in found_3rd_party_urls:
                                        found_3rd_party_urls.append(u)
                            except Exception as e:
                                continue
                except Exception as e:
                    pass
            except Exception as e:
                continue
    except Exception as e:
        pass
    return found_urls, found_3rd_party_urls

def js_file_crawler(js_links, output_dir):
    ABSOLUTE_URL_RE = re.compile(r'https?://[^\s\'"\\)>]+')
    # LOCAL_PATH_RE = re.compile(r'[`"\'](/[a-zA-Z0-9_\-./&?=]+)[`"\']') # More conservative
    LOCAL_PATH_RE = re.compile(r'[`"\'](/[a-zA-Z0-9_\-./&?=${}%#]+)[`"\']') # More generous
    
    def resolve_urls(js_body, js_url):
        urls = []
        for u in ABSOLUTE_URL_RE.findall(js_body):
            try:
                if not u or u.startswith("data:"):
                    continue
                if urlparse(u).path == "":
                    u = u.replace("?", "/?").replace("#", "/#") if "?" in u or "#" in u else u + "/"
                urls.append(u)
            except Exception as e:
                pass
        for u in LOCAL_PATH_RE.findall(js_body):
            try:
                if not u or u.startswith("data:"):
                    continue
                urls.append(urljoin(js_url, u))
            except Exception as e:
                pass
        return urls
    
    def is_a_valid_url(u):
        if not isinstance(u, str):
            return False
        try:
            parsed = urlparse(u)
            return parsed.scheme.lower() in ("http", "https") and bool(parsed.netloc)
        except Exception as e:
            return False
    
    def bucket_url(u, base_domain, general, thirdparty):
        try:
            _, u_domain = tld_extraction(u)
            if u_domain == base_domain:
                if u not in general:
                    general.append(u)
            elif "w3.org" not in u:
                if u not in thirdparty:
                    thirdparty.append(u)
        except Exception as e:
            pass
    
    def parse_js_files(js_body, js_url, general, thirdparty):
        if (
            not isinstance(js_body, str) or not isinstance(js_url, str)
            or not isinstance(general, list) or not isinstance(thirdparty, list)
        ):
            return general, thirdparty
        try:
            _, base_domain = tld_extraction(js_url)
        except Exception as e:
            return general, thirdparty
        for u in resolve_urls(js_body, js_url):
            if is_a_valid_url(u):
                bucket_url(u, base_domain, general, thirdparty)
        return general, thirdparty

    general, thirdparty = [], []
    jsrespcache = {}
    js_output_dir = str(f"{output_dir}/javascript")
    Path(js_output_dir).mkdir(parents=True, exist_ok=True)

    for js_url in js_links:
        try:
            resp = asyncio.run( make_aio_request(js_url) )
            general, thirdparty = parse_js_files(resp['body'], resp['url'], general, thirdparty)
            try:
                if resp['url'] not in jsrespcache:
                    if str(resp['status']) in {"200", "206"}:
                        jsrespcache[str(js_url)] = {
                            "status": str(resp['status'])
                        }
                        parsed_path = Path(urlparse(resp['url']).path)
                        js_subdir = parsed_path.parent
                        js_filepath = parsed_path
                        try:
                            Path(f"{js_output_dir}/{js_subdir}").mkdir(parents=True, exist_ok=True)
                            Path(f"{js_output_dir}/{js_filepath}").write_text(resp['body'], encoding="utf-8")
                        except Exception as e:
                            continue
                    else:
                        jsrespcache[str(js_url)] = {
                            "status": str(resp['status'])
                        }
            except:
                continue
        except Exception as e:
            continue

    # Loop through and try to find any and all Sourcemap disclosures
    found_sourcemap = False
    for js_url in js_links:
        try:
            resp = asyncio.run( make_aio_request(f"{js_url}.map") )
            try:
                if str(resp['status']) in {"200", "206"}:
                    parsed_path = Path(urlparse(resp['url']).path)
                    js_subdir = parsed_path.parent
                    js_filepath = parsed_path
                    try:
                        Path(f"{js_output_dir}/{js_subdir}").mkdir(parents=True, exist_ok=True)
                        Path(f"{js_output_dir}/{js_filepath}").write_text(resp['body'], encoding="utf-8")
                    except Exception as e:
                        continue
                    if jsrespcache[str(js_url)]["status"] in {"200", "206"}:
                        try:
                            sourcemap_body = resp['body']
                            for prefix in [")]}'", ")]}"]:
                                if sourcemap_body.startswith(prefix):
                                    sourcemap_body = sourcemap_body.split("\n", 1)[1]
                                    break
                            data = json.loads(sourcemap_body)
                            for source, content in zip(data.get("sources", []), data.get("sourcesContent", [])):
                                if content:
                                    out_path = Path(f"{js_output_dir}/unminified") / Path(source).name
                                    out_path.parent.mkdir(parents=True, exist_ok=True)
                                    out_path.write_text(content, encoding="utf-8")
                            print(f"Potential Sourcemap Disclosure :: {js_url}")
                            found_sourcemap = True
                        except Exception as e:
                            continue
            except Exception as e:
                continue
        except Exception as e:
            continue
    if not found_sourcemap:
        print(Style.RESET_ALL + Fore.RED + Style.DIM + "[!] No sourcemap files detected")
    return general, thirdparty

#
#### WQ Core Logic HTTP Verbs, Hosts, Enum, Protos
#
def wq_verbs(main_output_dir, verb, url, hostheader, user_agent, baseline_req, all_urls, third_party_urls):
    if verb == 'GET':
        all_urls, third_party_urls = wq_messages(main_output_dir, baseline_req, all_urls, third_party_urls, url, 'GET')
    else:
        try:
            if verb == 'CONNECT':
                response = make_requests_request(
                    f"{url}", hostheader, verb, '', False, user_agent
                ) # Requests library per how it handles the RFC
                all_urls, third_party_urls = wq_messages(main_output_dir, response, all_urls, third_party_urls, url, verb)
            else:
                response = asyncio.run(
                    make_aio_request(
                        f"{url}", hostheader, verb, "", False, False, user_agent
                    )
                ) # AIO HTTP Request
                all_urls, third_party_urls = wq_messages(main_output_dir, response, all_urls, third_party_urls, url, verb)
        except Exception as e:
            print(f"Ruh roh...")
    return all_urls, third_party_urls

def wq_hosts(main_output_dir, host, url, user_agent, all_urls, third_party_urls):
    try:
        response = asyncio.run(
            make_aio_request( url, host, 'GET', "", False, False, user_agent )
        )
        all_urls, third_party_urls = wq_messages(main_output_dir, response, all_urls, third_party_urls, url, "", str(host))
    except Exception as e:
        print(Style.RESET_ALL + Fore.RED + Style.DIM + host + ":\t\tAnomaly or Redirect Issue Detected!" + Style.RESET_ALL)
    return all_urls, third_party_urls

def wq_enum(
    main_output_dir, enum, url, hostheader, user_agent, baseline_req, robots_req, sitemap_xml_req,
    manifest_json_req, package_json_req, server_status_req, all_urls, third_party_urls
):
    if enum == "baseline":
        all_urls, third_party_urls = wq_messages(main_output_dir, baseline_req, all_urls, third_party_urls, url, "", "", "baseline")
    elif enum == "robots.txt":
        all_urls, third_party_urls = wq_messages(main_output_dir, robots_req, all_urls, third_party_urls, url, "", "", "robots.txt")
    elif enum == "sitemap.xml":
        all_urls, third_party_urls = wq_messages(main_output_dir, sitemap_xml_req, all_urls, third_party_urls, url, "", "", "sitemap.xml")
    elif enum == "manifest.json":
        all_urls, third_party_urls = wq_messages(main_output_dir, manifest_json_req, all_urls, third_party_urls, url, "", "", "manifest.json")
    elif enum == "package.json":
        all_urls, third_party_urls = wq_messages(main_output_dir, package_json_req, all_urls, third_party_urls, url, "", "", "package.json")
    elif enum == "server-status":
        all_urls, third_party_urls = wq_messages(main_output_dir, server_status_req, all_urls, third_party_urls, url, "", "", "server-status")
    else:
        try:
            response = asyncio.run(
                make_aio_request(
                    f"{url}", hostheader, 'GET', enum, True, False, user_agent
                )
            )
            all_urls, third_party_urls = wq_messages(main_output_dir, response, all_urls, third_party_urls, url, "", "", enum)
        except:
            print("Ruh roh...")
    return all_urls, third_party_urls

def wq_protos(main_output_dir, proto, url, user_agent, host_header, all_urls, third_party_urls):
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
        
        all_urls, third_party_urls = wq_messages(main_output_dir, original_resp, all_urls, third_party_urls, url, "", "", "", f"NORMAL HTTP/{proto}")
        all_urls, third_party_urls = wq_messages(main_output_dir, response, all_urls, third_party_urls, url, "", "", "", f"SOCKET HTTP/{proto}")
        print()
    except Exception as e:
        print(Style.RESET_ALL + Fore.RED + Style.DIM + host + ":\t\tProtoscan Issue Detected!" + Style.RESET_ALL)
    return all_urls, third_party_urls

#
#### Main Logic for WisQuas CLI
#
def wisquas_cli_main():
    # URL Arrays
    all_urls = []
    third_party_urls = []
    
    try: # Parse URL
        url = sys.argv[2]
        if url == "http:///" or url == "https:///" or url == "http://" or url == "https://":
            sys.exit(1)
        if not url.startswith("http://") and not url.startswith("https://"):
            sys.exit(1)
    except:
        helpme()

    # Set the main_output_dir
    try:
        purl = urlparse(url)
        phostname = purl.hostname.replace(".", "-")
        pport = purl.port or {"http": "80", "https": "443"}.get(purl.scheme, 80)
        main_output_dir = f"{phostname}-{pport}-{str(int(time.time()))}"
        Path(main_output_dir).mkdir(parents=True, exist_ok=True)
    except:
        helpme()
    
    # Parse the agent
    agent = sys.argv[1]
    if agent not in ["-1","-2"]:
        helpme()

    try: # Parse host header
        custom_host_header = sys.argv[3]
    except:
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
    wq_enum(main_output_dir, "baseline", url, hostheader, user_agent, baseline_req, {}, {}, {}, {}, {}, all_urls, third_party_urls)
    for enum in enum_payloads:
        if enum == "robots.txt":
            wq_enum(main_output_dir, enum, url, hostheader, user_agent, {}, robots_req, {}, {}, {}, {}, all_urls, third_party_urls)
        elif enum == "sitemap.xml":
            wq_enum(main_output_dir, enum, url, hostheader, user_agent, {}, {}, sitemap_xml_req, {}, {}, {}, all_urls, third_party_urls)
        elif enum == "manifest.json":
            wq_enum(main_output_dir, enum, url, hostheader, user_agent, {}, {}, {}, manifest_json_req, {}, {}, all_urls, third_party_urls)
        elif enum == "package.json":
            wq_enum(main_output_dir, enum, url, hostheader, user_agent, {}, {}, {}, {}, package_json_req, {}, all_urls, third_party_urls)
        elif enum == "server-status":
            wq_enum(main_output_dir, enum, url, hostheader, user_agent, {}, {}, {}, {}, {}, server_status_req, all_urls, third_party_urls)
        else:
            wq_enum(main_output_dir, enum, url, hostheader, user_agent, {}, {}, {}, {}, {}, {}, all_urls, third_party_urls)

    #######    HTTP VERBS   ###############################################
    print()
    print(Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + "\nHTTP VERB ENUMERATIONS :: response_code / length / cookies / headers / server / title / vhost_leak / location:" + Style.RESET_ALL + Fore.GREEN + Style.NORMAL)
    for verb in verbs:
        if verb == 'GET':
            wq_verbs(main_output_dir, verb, url, hostheader, user_agent, baseline_req, all_urls, third_party_urls)
        else:
            wq_verbs(main_output_dir, verb, url, hostheader, user_agent, {}, all_urls, third_party_urls)

    #######    HTTP HOSTS ENUMERATIONS   ###############################################
    print()
    print(Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + "\n\nHTTP HOST HEADER ENUMERATIONS :: response_code / length / cookies / headers / server / title / vhost_leak / location:" + Style.RESET_ALL + Fore.GREEN + Style.NORMAL)
    wq_hosts(main_output_dir, hosts, url, user_agent, all_urls, third_party_urls)
    for h in enum_hosts:
        wq_hosts(main_output_dir, h, url, user_agent, all_urls, third_party_urls)
    
    #######    Protoscan   ###############################################
    print()
    print(Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + "\n\nRUNNING PROTOCOL SCANNER :: response_code / length / cookies / headers / server / title / vhost_leak / location:" + Style.RESET_ALL + Fore.GREEN + Style.NORMAL)
    for proto in protos:
        wq_protos(main_output_dir, proto, url, user_agent, hostheader, all_urls, third_party_urls)
    
    #######    Allurls   ###############################################
    print()
    all_urls, third_party_urls = print_robots_text(robots_req, all_urls, third_party_urls, url, main_output_dir)
    print()
    all_urls, third_party_urls = print_sitemap_text(sitemap_xml_req, all_urls, third_party_urls, url, main_output_dir)

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

    # Final sort of allurls.txt and 3rdpartyurls.txt
    final_sort_urls_files(f"{main_output_dir}/allurls.txt")
    final_sort_urls_files(f"{main_output_dir}/3rdpartyurls.txt")

    # Run JS File Crawler to pull out URLs and API endpoints, and attempt to deminify JS sourcemaps
    print()
    print(Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + "\n\nRUNNING JS CRAWLER :: count" + Style.RESET_ALL + Fore.GREEN + Style.NORMAL)
    js_files = []
    for a in all_urls:
        if a.endswith(".js"):
            js_files.append(a)
    generaljs, thirdpartyjs = js_file_crawler(js_files, main_output_dir)
    print(Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + f"\nFOUND URLS COUNT :: " + str(len(generaljs)) + Style.RESET_ALL + Fore.GREEN + Style.NORMAL)
    print(Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + f"FOUND 3RD PARTY URLS COUNT :: " + str(len(thirdpartyjs)) + Style.RESET_ALL + Fore.GREEN + Style.NORMAL)
    with open(f"{main_output_dir}/jsurls.txt", "a") as f:
        for g in generaljs:
            f.write(f"{g}\n")
    with open(f"{main_output_dir}/3rdparty-jsurls.txt", "a") as f:
        for t in thirdpartyjs:
            f.write(f"{t}\n")

    print(Style.RESET_ALL + Fore.GREEN + Style.BRIGHT + "\n🐇🐇🐇🐇🐇 WISQUAS SCAN COMPLETE :: More info at https://gitlab.com/LostRabbitLabs 🐇🐇🐇🐇🐇\n" + Style.RESET_ALL)

if __name__ == "__main__":
    print(Style.RESET_ALL + Fore.MAGENTA + Style.NORMAL)
    print('🐇🐇🐇 Presented by Lost Rabbit Labs 🐇🐇🐇')
    print(Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)
    print('8   8  8          8""""8                   ')
    print('8   8  8 e  eeeee 8    8 e   e eeeee eeeee ')
    print('8e  8  8 8  8   " 8    8 8   8 8   8 8   " ')
    print('88  8  8 8e 8eeee 8    8 8e  8 8eee8 8eeee ')
    print('88  8  8 88    88 8 ___8 88  8 88  8    88 ')
    print('88ee8ee8 88 8ee88 8e8888 88ee8 88  8 8ee88\n')
    print('ˆˆˆˆˆˆˆˆ ˆˆ ˆˆˆˆˆ ˆˆˆˆˆˆ ˆˆˆˆˆ ˆˆ  ˆ ˆˆˆˆˆ')
    print(' Web Scanner & Anomaly Detector (v3.11.2026)')
    wisquas_cli_main()