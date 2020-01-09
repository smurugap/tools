# -*- coding: utf-8 eval: (yapf-mode 1) -*-
# February 24 2018, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2018, Deutsche Telekom AG.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from __future__ import absolute_import, division, unicode_literals, print_function, nested_scopes
from gevent import monkey
monkey.patch_all()
import gevent
try:
   import queue
except ImportError:
   import Queue as queue
import threading
import argparse
import datetime
import logging
import os
import platform
import socket
import sys
import time
from netconf import error, server, util
from netconf import nsmap_add, NSMAP
from lxml import etree
from jinja2 import Template
from datetime import datetime

nsmap_add("sys", "urn:ietf:params:xml:ns:yang:ietf-system")

debug=True
SYSINFO='system_info'
TEMPLATES = {'version': 'version.j2',
             'system_info': 'system_info.j2',
             'chassis_mac': 'chassis_mac.j2',
             'interfaces': 'interfaces.j2',
             'config_interfaces': 'config_interfaces.j2',
             'hardware_inventory': 'hardware_inventory.j2',
            }

def date_time_string(dt):
    tz = dt.strftime("%z")
    s = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")
    if tz:
        s += " {}:{}".format(tz[:-2], tz[-2:])
    return s


class SystemServer(object):
    def __init__(self, port, host_key, auth, debug, my_queue, version=None,
                 hostname='mock', tunnel_ip=None, macaddr=None, intf_count=10):
        self.version = version
        self.hostname = hostname
        self.tunnel_ip = tunnel_ip
        self.macaddr = macaddr
        self.intf_count = intf_count
        self.update_system_info()
        self.server = NetconfSSHServerWrapper(auth, self, port, host_key,
                                              debug, my_queue=my_queue)

    def nc_append_capabilities(self, capabilities):  # pylint: disable=W0613
        """The server should append any capabilities it supports to capabilities"""
        util.subelm(capabilities,
                    "capability").text = "urn:ietf:params:netconf:capability:xpath:1.0"
        util.subelm(capabilities, "capability").text = NSMAP["sys"]

    def close():
        self.server.close()

    def update_system_info(self):
        with open(TEMPLATES[SYSINFO], 'r') as fd:
            template = Template(fd.read())
        content = template.render(version=self.version, hostname=self.hostname)
        with open(SYSINFO, 'w+') as fd:
            fd.write(content)

    def _convert_template_to_xml(self, template, **kwargs):
        filename = TEMPLATES[template]
        with open(filename, 'r') as fd:
            template = Template(fd.read())
        content = template.render(**kwargs)
        return etree.fromstring(content)

    def rpc_get_configuration(self, session, rpc, *args, **kwargs):
        rpc = rpc.xpath('./get-configuration')[0]
        is_diff = rpc.get('compare') == 'rollback'
        if is_diff:
            reply = etree.Element('configuration-information')
            reply.append(etree.Element('configuration-output'))
            return reply
        is_committed = rpc.get('database') == 'committed'
        is_interfaces = rpc.xpath('./configuration/interfaces')
        is_roptions = rpc.xpath('./configuration/routing-options')
        if is_committed:
          if is_interfaces:
            return self._convert_template_to_xml('config_interfaces',
                                                 lo0_ip=self.tunnel_ip)
          elif is_roptions:
            reply = '<configuration>\n<routing-options>\n<static>\n<route>\n'+\
                '<name>0.0.0.0/0</name>\n<next-hop>10.87.101.13</next-hop>\n'+\
                '</route>\n</static>\n</routing-options>\n</configuration>'
            return etree.fromstring(reply)

    def rpc_get_interface_information(self, *args, **kwargs):
        return self._convert_template_to_xml('interfaces',
            count=self.intf_count, lo_ip=self.tunnel_ip)

    def rpc_load_configuration(self, session, rpc, config, *args, **kwargs):
        filename=datetime.now().strftime("%Y-%m-%d-%H:%M:%S.%f")+'.conf'
        with open(filename, 'w') as fd:
            fd.write(config.text)
        reply = etree.Element('ok')
        return reply

    def rpc_command(self, session, rpc):
        command = rpc.xpath('./command')[0].text
        filename = None
        if command == 'show chassis hardware':
            return self._convert_template_to_xml('hardware_inventory', hostname=self.hostname)
        elif command == 'show interfaces':
            return self.rpc_get_interface_information()
        elif command == 'show chassis mac-addresses':
            return self._convert_template_to_xml('chassis_mac', macaddr=self.macaddr)
        elif 'show version' in command:
            return self._convert_template_to_xml('version',
                hostname=self.hostname, version=self.version)
        elif 'lldp' in command:
            filename = 'lldp_info'
        with open(filename, 'r') as fd:
            content = fd.read()
        return etree.fromstring(content)

    def check_channel_exec_request(self, *args, **kwargs):
        return True

class NetconfSSHServerWrapper(server.NetconfSSHServer):
    def __init__(self, server_ctl=None, server_methods=None, port=830, host_key=None, debug=False, my_queue=None):
        self.server_methods = server_methods
        self.session_id = 1
        self.session_locks_lock = threading.Lock()
        self.session_locks = {
            "running": 0,
            "candidate": 0,
        }
        self.my_queue = my_queue
        super(server.NetconfSSHServer, self).__init__(
            server_ctl,
            server_session_class=NetconfServerSessionWrapper,
            port=port,
            host_key=host_key,
            debug=debug)

class NetconfServerSessionWrapper(server.NetconfServerSession):
    def __init__(self, channel, nc_server, unused_extra_args, debug):
        self.server = nc_server
        sid = self.server._allocate_session_id()
        self.methods = self.server.server_methods
        super(server.NetconfServerSession, self).__init__(channel, debug, sid)
        try:
            data = self.server.my_queue.get(timeout=5)
        except:
            super(server.NetconfServerSession, self)._open_session(True)

class SSHWrapper(server.SSHUserPassController):
    def __init__(self, my_queue=None, *args, **kwargs):
        self.my_queue = my_queue
        super(SSHWrapper, self).__init__(*args, **kwargs)

    def check_channel_exec_request(self, channel, command):
        self.my_queue.put('disable', False)
        if "show system information" in command:
            command = "cat %s"%SYSINFO
        process = gevent.subprocess.Popen(command, stdout=gevent.subprocess.PIPE,
                                          stdin=gevent.subprocess.PIPE,
                                          stderr=gevent.subprocess.PIPE,
                                          shell=True)
        gevent.spawn(self._read_response, channel, process)
        gevent.sleep(0)
        return True

    def _read_response(self, channel, process):
        gevent.sleep(0)
        print("Waiting for output")
        for line in process.stdout:
            channel.send(line)
        process.communicate()
        channel.send_exit_status(process.returncode)
        print("Command finished with return code %s"%process.returncode)
        # Let clients consume output from channel before closing
        gevent.sleep(.1)
        channel.close()
        gevent.sleep(0)

def main(*margs):
    parser = argparse.ArgumentParser("Example System Server")
    parser.add_argument(
        "--password", default="c0ntrail123", help='Netconf password')
    parser.add_argument("--username", default="root", help='Netconf username')
    parser.add_argument("--hostname", default="mock",
        help='Hostname of the device')
    parser.add_argument("--version", default="18.4R2.7",
        help='version on mock device')
    parser.add_argument("--tunnel_ip", required=True, help='loopback ip')
    parser.add_argument("--mac_addr", required=True, help='Chassiss mac address')
    parser.add_argument("--interfaces", default=10, type=int,
        help='Number of interfaces in the device')
    args = parser.parse_args(*margs)
    if debug:
        logging.basicConfig(level=logging.DEBUG)

    my_queue = queue.Queue()
    auth = SSHWrapper(username=args.username, password=args.password,
                      my_queue=my_queue)
    s = SystemServer(22, None, auth, debug, my_queue, version=args.version,
                     hostname=args.hostname, tunnel_ip=args.tunnel_ip,
                     macaddr=args.mac_addr, intf_count=args.interfaces)

    if sys.stdout.isatty():
        print("^C to quit server")
    try:
        while True:
            time.sleep(1)
    except Exception:
        print("quitting server")
    s.close()

if __name__ == "__main__":
    main()
