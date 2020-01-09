from fabric.operations import get, put, sudo, local
from fabric.api import run, env
from fabric.exceptions import CommandTimeout, NetworkError
from fabric.contrib.files import exists
from fabric.state import connections as fab_connections
from fabric.context_managers import settings, hide, cd

import re
import time
import os
import tempfile
import requests
from lxml import etree

VM_USERNAME='cirros'
VM_PASSWORD='gocubsgo'
HOST_USERNAME='root'
HOST_PASSWORD='c0ntrail123'
dir_path = os.path.dirname(os.path.realpath(__file__))
TCPSERVER = dir_path+'/tcpechoserver.py'
TCPCLIENT = dir_path+'/tcpechoclient.py'
UDPSERVER = dir_path+'/udpechoserver.py'
UDPCLIENT = dir_path+'/udpechoclient.py'
SIMULATOR = dir_path+'/simulator'

class AgentInspect(object):
    def __init__(self, server):
        self.server = server

    def get(self, path):
        url = "http://%s:8085/%s" % (self.server, path)
        resp = requests.get(url)
        if resp.status_code == 200:
            return etree.fromstring(resp.text)
        return None

    def get_local_ip(self, vmi_id):
        response = self.get('Snh_ItfReq?uuid=%s'%vmi_id)
        intf_list = response.xpath('./ItfResp/itf_list/list/ItfSandeshData') or \
                    response.xpath('./itf_list/list/ItfSandeshData')
        for intf in intf_list:
            for e in intf:  # intf replaces avn[0]
                if e.tag == 'mdata_ip_addr':
                    return e.text

class BMS(object):
    def __init__(self, mgmt_ip, username, password, interfaces=None, profile=None):
        self.mgmt_ip = mgmt_ip
        self.username = username
        self.password = password
        self.interfaces = interfaces
        self.profile = profile
        if self.profile:
            self.interface = profile.get('interface') or self.get_intf_name(profile['port_mac'])

    def run(self, cmd, namespace=None):
        if namespace:
            cmd = 'ip netns exec %s %s'%(namespace, cmd)
        output = remote_cmd('%s@%s'%(self.username, self.mgmt_ip),
                            cmd, password=self.password)
        return output

    def create_mock_server(self, qfx_name, index, address, macaddr, gw_ip, asn, peers):
        pif_count = self.profile.get('pifs') or 10
        intf_name = '%s.%s'%(self.interface[:6], index)
        ns_name = qfx_name
        #Create macvlan interface
        self.run('ip link set dev %s up'%self.interface)
        self.run('ip link add %s link %s type macvlan mode bridge'%(
                 intf_name, self.interface))
        #Create netns and link mvlan interface
        self.run('ip netns add %s'%ns_name)
        self.run('mkdir %s'%ns_name)
        self.run('ip link set netns %s %s'%(ns_name, intf_name))
        self.run('ip link set dev %s up'%intf_name, ns_name)
        self.run('ip addr add %s/24 dev %s'%(address, intf_name), ns_name)
        self.run('ip route add default via %s'%gw_ip, ns_name)
        #Copy mock server and the templates dir
        dest_dir = '%s@%s:%s' % (self.username, self.mgmt_ip, ns_name)
        remote_copy(SIMULATOR, dest_dir, dest_password=self.password)
        #Start the mock server
        app = 'python mockserver.py start '
        args = '--loopback %s --mac_addr %s --hostname %s --interfaces %s --asn %s --peers %s'%(
            address, macaddr, qfx_name, pif_count, asn, " ".join(peers))
        cwd = ns_name+'/'+os.path.basename(SIMULATOR)
        cmd = 'cd %s; %s'%(cwd, app + args)
        cmd = '/bin/sh -l -c "%s"'%cmd
        self.run(cmd, namespace=ns_name)
        print 'Started mock server', qfx_name, address

    def delete_mock_server(self, qfx_name):
        ns_name = qfx_name
        app = 'python mockserver.py stop '
        args = '--hostname %s'%qfx_name
        cwd = ns_name+'/'+os.path.basename(SIMULATOR)
        cmd = 'cd %s; %s'%(cwd, app + args)
        cmd = '/bin/sh -l -c "%s"'%cmd
        self.run(cmd, namespace=ns_name)
        print 'Stopped mock server', qfx_name

    def advertise_route(self, qfx_name, target, mac, ip, nh, vni):
        ns_name = qfx_name
        app = 'python mockserver.py advertise '
        route = 'rt=%s,mac=%s,ip=%s,vni=%s'%(target, mac, ip, vni)
        args = '--hostname %s --loopback %s --routes %s'%(
            qfx_name, nh, route)
        cwd = ns_name+'/'+os.path.basename(SIMULATOR)
        cmd = 'cd %s; %s'%(cwd, app + args)
        cmd = '/bin/sh -l -c "%s"'%cmd
        self.run(cmd, namespace=ns_name)
        print 'Advertised route mac:%s ip:%s vni:%s from host %s'%(mac, ip, vni, qfx_name)

    def withdraw_route(self, qfx_name, target, mac, ip, nh, vni):
        ns_name = qfx_name
        app = 'python mockserver.py withdraw '
        route = 'rt=%s,mac=%s,ip=%s,vni=%s'%(target, mac, ip, vni)
        args = '--hostname %s --loopback %s --routes %s'%(
            qfx_name, nh, route)
        cwd = ns_name+'/'+os.path.basename(SIMULATOR)
        cmd = 'cd %s; %s'%(cwd, app + args)
        cmd = '/bin/sh -l -c "%s"'%cmd
        self.run(cmd, namespace=ns_name)
        print 'Withdraw route mac:%s ip:%s vni:%s from host %s'%(mac, ip, vni, qfx_name)

class VM(object):
    def __init__(self, vmi_fqname, client_h):
        self.vmi_fqname = vmi_fqname
        self.client_h = client_h
        self._vm_id = None
        self._vmi_id = None
        self._vm_node_ip = None
        self._local_ip = None
        self._vm_ip = None

    @property
    def vm_id(self):
        if not self._vm_id:
            self._vm_id = self.client_h.get_vm_id(self.vmi_fqname)
        return self._vm_id

    @property
    def vmi_id(self):
        if not self._vmi_id:
            port_obj = self.client_h.read_port(fq_name=self.vmi_fqname)
            self._vmi_id = port_obj.uuid
        return self._vmi_id

    @property
    def vm_node_ip(self):
        if not self._vm_node_ip:
            self._vm_node = self.client_h.get_vm_node(self.vm_id)
        return self._vm_node

    @property
    def local_ip(self):
        if not self._local_ip:
            agent_h = AgentInspect(self.vm_node_ip)
            self._local_ip = agent_h.get_local_ip(self.vmi_id)
        return self._local_ip

    @property
    def vm_ip(self):
        if not self._vm_ip:
            self._vm_ip = self.client_h.get_vmi_ip(id=self.vmi_id)
        return self._vm_ip

    def run_cmd_on_vm(self, cmd, as_sudo=False,
                      as_daemon=False, pidfile=None):
        '''run cmds on VM

        '''
        vm_host_string = '%s@%s' % (VM_USERNAME, self.local_ip)
        output = remote_cmd(
            vm_host_string, cmd, gateway_password=HOST_PASSWORD,
            gateway='%s@%s' % (HOST_USERNAME, self.vm_node_ip),
            password=VM_PASSWORD,
            as_daemon=as_daemon
        )
        return output

    def copy_file_to_vm(self, localfile):
        dest_dir = '%s@%s:/tmp/%s' % (VM_USERNAME, self.local_ip, os.path.basename(localfile))
        dest_gw_login = "%s@%s" % (HOST_USERNAME, self.vm_node_ip)
        remote_copy(localfile, dest_dir, dest_password=VM_PASSWORD,
                    dest_gw=dest_gw_login, dest_gw_password=HOST_PASSWORD)
    # end copy_file_to_vm

    def start_traffic(self, protocol, port, mode=None, server=None):
        pid_file = '/tmp/%s-%s-%s.pid'%(server or 'server', protocol, port)
        stats_file = '/tmp/%s-%s-%s.stats'%(server or 'server', protocol, port)
        log_file = '/tmp/%s-%s-%s.log'%(server or 'server', protocol, port)
        if protocol.lower() == 'tcp':
            server_script = TCPSERVER
            client_script = TCPCLIENT
        elif protocol.lower() == 'udp':
            server_script = UDPSERVER
            client_script = UDPCLIENT
        if mode == 'server':
            cmd = '--start_port %s --end_port %s --pid_file %s --stats_file %s'%(
                  port, port, pid_file, stats_file)
            cmd = 'python /tmp/%s %s'%(os.path.basename(server_script), cmd)
            cmd = cmd + ' 0<&- &> %s'%log_file
            self.run_cmd_on_vm(cmd, as_daemon=True)
        elif mode == 'client':
            cmd = '--servers %s --dports %s --retry --slow --pid_file %s --stats_file %s'%(
                  server, port, pid_file, stats_file)
            cmd = 'python /tmp/%s %s'%(os.path.basename(client_script), cmd)
            cmd = cmd + ' 0<&- &> %s'%log_file+';ps ax'
            self.run_cmd_on_vm(cmd)

    def get_stats(self, protocol, port, server=None, poll=True):
        signal = '-USR1' if poll is True else ''
        pid_file = '/tmp/%s-%s-%s.pid'%(server or 'server', protocol, port)
        stats_file = '/tmp/%s-%s-%s.stats'%(server or 'server', protocol, port)
        log_file = '/tmp/%s-%s-%s.log'%(server or 'server', protocol, port)
        cmd = 'kill %s $(cat %s); sync; cat %s'%(signal, pid_file, stats_file)
        output = self.run_cmd_on_vm(cmd, as_sudo=False)
        if poll is False:
            self.run_cmd_on_vm('rm %s %s'%(pid_file, stats_file), as_sudo=False)
        pattern = 'dport: (?P<dport>\d+) -.* ip: (?P<ip>.*) - ' \
                   + 'sent: (?P<sent>\d+) - recv: (?P<recv>\d+)'
        stats = [m.groupdict() for m in re.finditer(pattern, output or '')]
        sent = sum([int(d['sent']) for d in stats])
        recv = sum([int(d['recv']) for d in stats])
        return (sent, recv)

    def stop_traffic(self, protocol, port, server=None):
        return self.get_stats(protocol, port, server=server, poll=False)

    def poll_traffic(self, protocol, port, server=None):
        return self.get_stats(protocol, port, server=server, poll=True)

def remote_cmd(host_string, cmd, password=None, gateway=None,
               as_daemon=False, gateway_password=None):
    if as_daemon:
        cmd = 'nohup ' + cmd + ' & '
    (username, host_ip) = host_string.split('@')
    shell = '/bin/sh -l -c'
    with settings(
            host_string=host_string,
            gateway=gateway,
            shell=shell,
            warn_only=True,
            disable_known_hosts=True,
            abort_on_prompts=False):
      with hide('everything'):
        update_env_passwords(host_string, password, gateway, gateway_password)
        output = sudo(cmd, timeout=15, pty=not as_daemon, shell=shell)
        real_output = remove_unwanted_output(output)
        return real_output

def remove_unwanted_output(text):
    """ Fab output usually has content like [ x.x.x.x ] out : <content>
    Args:
        text: Text to be parsed
    """
    if not text:
        return None

    return_list = text.split('\n')

    return_list1 = []
    for line in return_list:
        line_split = line.split(' out: ')
        if len(line_split) == 2:
            return_list1.append(line_split[1])
        else:
            if ' out:' not in line:
                return_list1.append(line)
    real_output = '\n'.join(return_list1)
    return real_output

def remote_copy(src, dest, src_password=None, src_gw=None, src_gw_password=None,
                dest_password=None, dest_gw=None, dest_gw_password=None,
                with_sudo=False, warn_only=True):
    # dest is local file path
    if re.match(r"^[\t\s]*/", dest):
        dest_node = None
        dest_path = dest
    # dest is remote path
    elif re.match(r"^.*:", dest):
        dest = re.split(':', dest)
        dest_node = dest[0]
        dest_path = dest[1]
    else:
        raise AttributeError("Invalid destination path - %s " % dest)

    # src is local file path
    if re.match(r"^[\t\s]*/", src):
        if os.path.exists(src):
            src_node = None
            src_path = src
        else:
            raise IOError("Source not found - %s No such file or directory" % src)
    # src is remote path
    elif re.match(r"^.*:", src):
        src = re.split(':', src)
        src_node = src[0]
        src_path = src[1]
    else:
        raise AttributeError("Invalid source path - %s" % src)

    if src_node:
        # Source is remote
        with settings(host_string=src_node, gateway=src_gw,
                      warn_only=True, disable_known_hosts=True,
                      abort_on_prompts=False):
            update_env_passwords(src_node, src_password, src_gw, src_gw_password)
            try:
                if exists(src_path, use_sudo=with_sudo):
                    if dest_node:
                        # Both source and destination are remote
                        local_dest = tempfile.mkdtemp()
                        get(src_path, local_dest)
                        src_path = os.path.join(local_dest, os.listdir(local_dest)[0])
                    else:
                        # Source is remote and destination is local
                        # Copied to destination
                        get(src_path, dest_path)
                        return True
                else:
                    raise IOError("Source not found - %s No such file or directory" % src)
            except NetworkError:
                return False

    if dest_node:
        # Source is either local or remote
      with hide('everything'):
        with settings(host_string=dest_node, gateway=dest_gw,
                      warn_only=True, disable_known_hosts=True,
                      abort_on_prompts=False):
            update_env_passwords(dest_node, dest_password, dest_gw, dest_gw_password)
            try:
                put(src_path, dest_path, use_sudo=True)
                return True
            except NetworkError:
                pass
    else:
        # Both are local
        local("cp -r %s %s" % (src_path, dest_path))
        return True


def update_env_passwords(host, password=None, gateway=None, gateway_password=None):
    env.forward_agent = True
    gateway_hoststring = "fake_gateway"
    if gateway:
        gateway_hoststring = (gateway if re.match(r'\w+@[\d\.]+:\d+', gateway)
                              else gateway + ':22')
    node_hoststring = (host
                       if re.match(r'\w+@[\d\.]+:\d+', host)
                       else host + ':22')
    if password:
        env.passwords.update({node_hoststring: password})
        # If gateway_password is not set, guess same password
        # (if key is used, it will be tried before password)
        if not gateway_password:
            env.passwords.update({gateway_hoststring: password})

    if gateway_password:
        env.passwords.update({gateway_hoststring: gateway_password})
        if not password:
            env.passwords.update({node_hoststring: gateway_password})
