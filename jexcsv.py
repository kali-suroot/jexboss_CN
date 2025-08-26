"""
Check URLs for JBoss vulnerabilities in bulk and output results to a CSV file

Copyright 2016 Sean Whalen

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
批量检查URL是否存在JBoss漏洞，并将结果输出到CSV文件

版权所有 2016 Sean Whalen

根据 Apache 许可证 2.0 版本授权
（"许可证"）；除非符合许可证要求，否则不得使用此文件。
您可以在以下网址获取许可证副本：

    http://www.apache.org/licenses/LICENSE-2.0

除非适用法律要求或书面同意，否则按"原样"分发软件，
没有任何明示或暗示的保证或条件。
请参阅许可证了解具体的语言权限和限制。
"""

from argparse import ArgumentParser
from csv import DictWriter

from jexboss import check_vul

__version__ = "1.0.0"
__author__ = "Sean Whalen - @SeanTheGeek"

args = ArgumentParser(description=__doc__)
args.add_argument("input", help="输入文件路径")
args.add_argument("output", help="输出文件路径")
args = args.parse_args()

paths = {
    "jmx-console": "/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system:type=ServerInfo",
    "web-console": "/web-console/ServerInfo.jsp",
    "JMXInvokerServlet": "/invoker/JMXInvokerServlet"
}

results = []

with open(args.input, "r") as input_file:
    urls = input_file.readlines()

for url in urls:
    if url == "":
        continue
    if not url.startswith("http"):
        url = "http://{0}".format(url)
    url = url.strip()
    if url.endswith("/"):
        url = url[:-1]

    url_results = check_vul(url)
    for key in url_results.keys():
        if url_results[key] == 200 or url_results[key] == 500:
            full_url = "{0}{1}".format(url, paths[key])
            result = dict(
                base_url=url, 
                vulnerability=key, 
                full_url=full_url, 
                status_code=url_results[key]
            )
            results.append(result)

fields = ["base_url", "vulnerability", "full_url", "status_code"]
with open(args.output, "w", newline='') as output_file:
    writer = DictWriter(output_file, fields)
    writer.writeheader()
    writer.writerows(results)
