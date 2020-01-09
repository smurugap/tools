from gevent import monkey
monkey.patch_all()
import sys
import os
import time
import gevent
import socket
import logging
import datetime
import argparse
import threading
import subprocess
import Queue as queue
from lxml import etree
from jinja2 import Template
from datetime import datetime
from netconf import error, server, util, nsmap_add, NSMAP

nsmap_add("sys", "urn:ietf:params:xml:ns:yang:ietf-system")

debug=True
SYSINFO = 'system_info'
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

CONFIG = '''process announce {
    run nc -l -k -U %s;
    encoder text;
}
'''
PEER_CONFIG = '''
neighbor %s {
    peer-as %s;
    local-as %s;
    local-address %s;
    router-id %s;
    api {
        processes [announce];
    }
}'''

class ExaBGPWrapper(object):
    def __init__(self, hostname):
        self.hostname = hostname
        self.config_file = '/tmp/'+hostname+'-exabgp.conf'
        self.log_file = '/tmp/'+hostname+'-exabgp.log'
        self.sock_file = '/run/'+hostname+'-exabgp.sock'
        self.pid_file = '/run/'+hostname+'-exabgp.pid'

    def start(self, neighbors, loopback, asn):
        with open(self.config_file, 'w') as f:
            config = CONFIG %self.sock_file
            f.write('%s\n' % config)
            for neighbor in neighbors:
                peer_config = PEER_CONFIG % (neighbor, asn, asn, loopback, loopback)
                f.write('%s\n' % peer_config)
        cmd = 'env exabgp.daemon.user=root exabgp.daemon.pid=%s exabgp.daemon.daemonize=true exabgp.log.destination=%s exabgp %s'%(
            self.pid_file, self.log_file, self.config_file)
        subprocess.call(cmd, shell=True)

    def stop(self):
        cmd = 'kill $(cat %s)'%self.pid_file
        subprocess.call(cmd, shell=True)
        try:
            os.remove(self.config_file)
        except OSError:
            pass
        try:
            os.remove(self.sock_file)
        except OSError:
            pass
        try:
            os.remove(self.pid_file)
        except OSError:
            pass

    def advertise(self, loopback, routes, withdraw=False):
        ''' list of routes in the format rt=target:64512:11,mac=aa:bb:cc:dd:ee:ff,ip=10.10.10.1,vni=9999 '''
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self.sock_file)
        route_cmds = list()
        advertise = 'withdraw' if withdraw else 'announce'
        for route in routes:
            rt_dict = {'next-hop': loopback, 'rd': loopback+':100',
                       'label': 0, 'esi': 0}
            attr_dict = {entry.split("=")[0]:entry.split("=")[1]
                 for entry in route.split(",")}
            for k,v in attr_dict.items():
                if k == 'rt':
                    rt_dict['extended-community'] = "[ %s 0x030c000000000008 ]"%v
                elif k == 'vni':
                    rt_dict['etag'] = v
                else:
                    rt_dict[k] = v
            route_cmd = advertise + ' evpn '+' '.join("%s %s"%(key, val)
                for (key, val) in rt_dict.items()) + os.linesep
            sock.sendall(route_cmd.encode('utf-8'))
        sock.close()

def daemon(fn, pidfile, logfile, parent_callback=False, *args, **kwargs):
        try:
            pid = os.fork()
            if pid > 0:
                if parent_callback:
                    pid = os.fork()
                    if pid == 0:
                        return
                # Exit first parent
                sys.exit(0)
        except OSError, e:
            sys.exit(1)

        # Decouple from parent environment
#        os.chdir("/")
        os.setsid()
        os.umask(0)
        sys.stdout = open(logfile, 'a+')
        sys.stderr = open(logfile, 'a+')

        # Do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # Exit from second parent; print eventual PID before exiting
                with open(pidfile, 'w') as f:
                    f.write('%s\n'%pid)
                sys.exit(0)
        except OSError, e:
            sys.exit(1)
        fn(*args, **kwargs)

class NetconfServer(object):
    def __init__(self, hostname):
       self.hostname = hostname
       self.pid_file = '/run/'+hostname+'-netconf.pid'
       self.log_file = '/tmp/'+hostname+'-netconf.log'

    def stop(self):
        cmd = 'kill $(cat %s)'%self.pid_file
        subprocess.call(cmd, shell=True)
        try:
            os.remove(self.pid_file)
        except OSError:
            pass

    def start(self, *args, **kwargs):
        args = (self.hostname,)+args
        daemon(self._start, self.pid_file, self.log_file, True, *args, **kwargs)

    @staticmethod
    def _start(hostname, username, password, version, loopback, mac_addr, interfaces):
        logging.basicConfig(level=logging.DEBUG)
        my_queue = queue.Queue()
        auth = SSHWrapper(username=username, password=password, my_queue=my_queue)
        s = NetconfServerWrapper(22, None, auth, True, my_queue, version=version,
                         hostname=hostname, tunnel_ip=loopback,
                         macaddr=mac_addr, intf_count=interfaces)
        try:
            while True:
                time.sleep(1)
        except:
            pass
        s.close()

class NetconfServerWrapper(object):
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
        with open('current_config.conf', 'w') as fd:
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

def parse_cli(args):
    parser = argparse.ArgumentParser("Mock Physical Router (Leaf)")
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument("--hostname", required=True, help='Hostname of the device')
    subparsers = parser.add_subparsers(title="actions", dest='action')
#    subparsers.required = True
    parser_start = subparsers.add_parser("start", parents=[parent_parser],
        add_help=False,
        description="Start physical server simulator",
        help="Start the physical server simulator")
    parser_start.add_argument("--username", default="root", help='Netconf username')
    parser_start.add_argument("--password", default="c0ntrail123", help='Netconf password')
    parser_start.add_argument("--version", default="18.4R2.7", help='version on simulated device')
    parser_start.add_argument("--loopback", required=True, help='loopback ip')
    parser_start.add_argument("--mac_addr", required=True, help='Chassiss mac address')
    parser_start.add_argument("--interfaces", default=10, type=int, help='Number of interfaces in the device')
    parser_start.add_argument("--peers", action='store', default=[], nargs='+', help='Space separated list of BGP neighbors')
    parser_start.add_argument("--asn", required=True, help='overlay ASN number')
    parser_stop = subparsers.add_parser("stop", parents=[parent_parser],
        add_help=False, help="Stop the physical server simulator")
    parser_advertise = subparsers.add_parser("advertise", parents=[parent_parser],
        add_help=False, help="Advertise evpn routes")
    parser_advertise.add_argument("--loopback", required=True, help='loopback ip')
    parser_advertise.add_argument("--routes", action='store', default=[], nargs='+', help='Space separated list of routes')
    parser_withdraw = subparsers.add_parser("withdraw", parents=[parent_parser],
        add_help=False, help="Withdraw advertised evpn routes")
    parser_withdraw.add_argument("--loopback", required=True, help='loopback ip')
    parser_withdraw.add_argument("--routes", action='store', default=[], nargs='+', help='Space separated list of routes')
    pargs = parser.parse_args(args)
    return pargs

def main(oper, hostname, pargs):
    bgp = ExaBGPWrapper(hostname)
    netconf = NetconfServer(hostname)
    if oper.lower() == 'stop':
        netconf.stop()
        bgp.stop()
    elif oper.lower() == 'start':
        bgp.start(pargs.peers, pargs.loopback, pargs.asn)
        netconf.start(pargs.username, pargs.password, pargs.version, pargs.loopback, pargs.mac_addr, pargs.interfaces)
    elif oper.lower() == 'advertise':
        bgp.advertise(pargs.loopback, pargs.routes)
    elif oper.lower() == 'withdraw':
        bgp.advertise(pargs.loopback, pargs.routes, withdraw=True)
    elif getattr(obj, oper.lower(), None):
        fn = getattr(obj, oper.lower())
        fn()
    else:
        raise Exception()

if __name__ == '__main__':
    pargs = parse_cli(sys.argv[1:])
    main(pargs.action, pargs.hostname, pargs)
