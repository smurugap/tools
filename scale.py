import argparse
import random
import socket
import struct
import os
import sys
import time
import signal
import string
from netaddr import *
from datetime import datetime
from multiprocessing import Process, Queue
from neutronclient.neutron import client as neutron_client
try:
    from vnc_api.vnc_api import *
except:
    pass

from novaclient import client as nova_client
from keystoneclient.v2_0 import client as ks_client

alloc_addr_list = list()

class config(object):
    def __init__(self, args):
        self._args = args
        self.auth_url = 'http://%s:35357/v2.0' % self._args.keystone_ip
        self.admin_obj = Openstack(self.auth_url,
                                   self._args.admin_username,
                                   self._args.admin_password,
                                   self._args.admin_tenant)
        if self._args.vnc:
            self.obj = VNC(self.auth_url,
                           self._args.username,
                           self._args.password,
                           self._args.tenant,
                           self._args.api_server_ip,
                           self._args.api_server_port)
        else:
            self.obj = Openstack(self.auth_url,
                                 self._args.username,
                                 self._args.password,
                                 self._args.tenant)

    def verify(self):
        self.verify_compute_hosts()

    def pre_verify(self):
        self.verify_compute_hosts()

    def verify_compute_hosts(self):
        ''' Check whether all compute nodes are up '''
        hosts = self.admin_obj.nova.services.list(binary='nova-compute')
        computes = [h.host for h in hosts if h.status == 'enabled' and h.state == 'up']
        hosts = list(map((lambda x: x.host), hosts))
        if set(hosts) - set(computes):
            raise Exception('Few hosts are down %s'%list(set(hosts) - set(computes)))
        self.computes = computes

    def pre_conf(self):
        ''' Create certain objects before staring test '''
        if (self._args.n_ports or self._args.n_vms)\
            and not self._args.n_vns:
            vn_name=random_string('VN')
            self.obj.create_network(vn_name, mask=16)

        if self._args.n_sgs:
           sg_name=random_string('SG')
           self.obj.create_sg(sg_name)

        if self._args.n_fips:
            vn_name=random_string('EXT-VN')
            self.admin_obj.create_network(vn_name, mask=16, external=True)

    def run(self):
        ''' Run Scale test '''
# ToDo: Need to be modularized
        self.process= list()
        self.id_obj= list()
        for i in range(self._args.n_process):
            queue = Queue()
            self.process.append(Process(target=self.start, args=(i, queue)))
            self.process[i].queue = queue

        print 'Time at start ', time.strftime("%H:%M:%S:")
        start_time = datetime.now()
        for i in range(self._args.n_process):
            self.process[i].start()

        '''
        # Wait for 60 seconds then terminate all the process
        time.sleep(60)
        time.sleep(3) # Buffer time before instantiating terminate
        for i in range(self._args.n_process):
            self.process[i].terminate()
        '''

        for i in range(self._args.n_process):
            self.process[i].join()
            self.id_obj.append(self.process[i].queue.get(timeout=2))

        success = 0
        for i in range(self._args.n_process):
            if self.process[i].exitcode == 0:
                success += 1

        print 'Time at End ', time.strftime("%H:%M:%S:")
        end_time = datetime.now()
        print 'Time to create objects', end_time - start_time
        print 'Success Percentage: %s%%'%((success * 100)/self._args.n_process)

    def start(self, index, queue):
        try:
            # Create virtual network
            for vn_index in range(index, index+self._args.n_vns):
                vn_name='VN%d'%vn_index
                self.obj.create_network(vn_name=vn_name)

            for vn_name in self.obj.id.vn_uuid.keys():
            # Create Ports
                for port_index in range(index, index+self._args.n_ports):
                    port_name='%s-Port%d'%(vn_name, port_index)
                    self.obj.create_port(vn_name, port_name)

            # Create virtual machines
                for vm_index in range(index, index+self._args.n_vms):
                    vm_name = '%s-VM%d'%(vn_name, vm_index)
                    port_name='%s-Port%d'%(vn_name, vm_index)
                    self.obj.create_vm(port_name=port_name, image_id=self._args.image_id, vm_name=vm_name, vn_name=vn_name)

            # Create Security Group
            for sg_index in range(index, index+self._args.n_sgs):
                sg_name='SG%d'%sg_index
                self.obj.create_sg(sg_name)

            # Create Security Group Rules
            for sg_name in self.obj.id.sg_id.keys():
                cidr = get_randmon_cidr(mask=29)
                for rule_index in range(index, index+self._args.n_sg_rules):
                    self.obj.create_sg_rule(sg_name, rule_index+1000, rule_index+1000, cidr)

            # Create Router
            for rtr_index in range(index, index+self._args.n_routers):
                router_name='RTR%d'%rtr_index
                self.obj.create_router(router_name)

            # Create Floating IP
            for fip_index in range(index, index+self._args.n_fips):
                self.obj.create_floatingip(self.admin_obj.ext_vn_uuid)
        except KeyboardInterrupt:
            print 'Got SIGTERM'
        queue.put(self.obj.id)

# A Class of UUIDs
class id(object):
    vn_obj= dict()
    vn_uuid= dict()
    subnet_uuid= dict()
    port_id= dict()
    sg_id= dict()
    rule_id= dict()
    router_id= dict()
    fip_id= list()
    vm_id= dict()

class Openstack(object):
    def __init__(self, auth_url, username, password, tenant):
        ''' Get keystone client obj '''
        self.keystone = ks_client.Client(username=username,
                                  password=password,
                                  tenant_name=tenant,
                                  auth_url=auth_url,
                                  insecure=True)
        self.tenant_id = self.keystone.auth_tenant_id
        ''' Get nova client handle '''
        self.nova = nova_client.Client('2',
                                  auth_url=auth_url,
                                  username=username,
                                  api_key=password,
                                  project_id=tenant,
                                  insecure=True)
        ''' Get neutron client handle '''
        ''' Using tenant name in place of ID, Can be changed to tenant_id=self.tenant_id '''
        self.neutron = neutron_client.Client('2.0',
                                  auth_url=auth_url,
                                  username=username,
                                  password=password,
                                  tenant_name=tenant,
                                  insecure=True)
        self.id= id()

    def create_network(self, vn_name, mask=24, external=False):
        ''' Create Network via Neutron client call '''
        cidr = get_randmon_cidr(mask=mask)
        vn_dict = {'name': vn_name}
        if external:
            vn_dict['router:external'] = True
        response = self.neutron.create_network({'network': vn_dict})

        ''' Store VN uuid and subnet uuid dicts '''
        net_id = response['network']['id']
        if external:
            self.ext_vn_uuid = net_id
        else:
            self.id.vn_uuid[vn_name] = net_id
        response = self.neutron.create_subnet({'subnet':
                                              {'cidr': cidr,
                                               'ip_version': 4,
                                               'network_id': net_id
                                              }})
        self.id.subnet_uuid[vn_name] = response['subnet']['id']

    def create_port(self, vn_name, port_name):
        ''' Create port using Neutron api '''
        port_dict = {'network_id': self.id.vn_uuid[vn_name]}
        if self.id.subnet_uuid.has_key(vn_name):
            port_dict['fixed_ips'] = [{'subnet_id': self.id.subnet_uuid[vn_name]}]
        response = self.neutron.create_port({'port': port_dict})
        ''' Store Port UUID's '''
        self.id.port_id[port_name] = response['port']['id']

    def create_floatingip(self, ext_vn_uuid):
        ''' Create Floating IP '''
        floatingip_dict = {'floating_network_id': ext_vn_uuid}
        response = self.neutron.create_floatingip({'floatingip': floatingip_dict})
        self.id.fip_id.append(response['floatingip']['id'])

    def create_router(self, router_name):
        ''' Create Logical Router '''
        router_dict = {'name': router_name, 'admin_state_up': True}
        response = self.neutron.create_router({'router': router_dict})
        self.id.router_id[router_name] = response['router']['id']

    def create_sg(self, sg_name):
        ''' Create Security Group '''
        sg_dict = {'name': sg_name}
        response = self.neutron.create_security_group({'security_group': sg_dict})
        self.id.sg_id[sg_name] = response['security_group']['id']

    def create_sg_rule(self, sg_name, min, max, cidr='0.0.0.0/0', direction='ingress', proto='tcp'):
        sg_id = self.id.sg_id[sg_name]
        rule_dict = {'security_group_id': sg_id, 'direction': direction, 'remote_ip_prefix': cidr,
                     'protocol': proto, 'port_range_min': min, 'port_range_max': max}
        print rule_dict
        response = self.neutron.create_security_group_rule({'security_group_rule': rule_dict})
        if sg_name not in self.id.rule_id:
            self.id.rule_id[sg_name] = list()
        self.id.rule_id[sg_name].append(response['security_group_rule']['id'])

    def create_vm(self, vm_name, image_id, port_name=None, vn_name=None, compute_host=None, zone='nova'):
        ''' Create virtual machine '''
        nics=[]
        launch_on=None
        port_id=None
        ''' Few harcoded values '''
        flavor=1 # m1.tiny

        if port_name in self.id.port_id:
            port_id = self.id.port_id[port_name]
        if port_id is not None:
            nics = [{'port-id': port_id}]
        else:
            nics = [{'net-id': self.id.vn_uuid[vn_name]}]

        if compute_host:
            launch_on = zone + ':' + compute_host

        response = self.nova.servers.create(name=vm_name,
                                            flavor=flavor,
                                            image=image_id,
                                            nics=nics,
                                            availability_zone=launch_on)
        self.id.vm_id[vm_name] = response.id

class VNC(Openstack):
    def __init__(self, auth_url, username, password, tenant, ip, port):
        super(VNC, self).__init__(auth_url, username, password, tenant)
        self.vnc = VncApi(api_server_host=ip,
                          api_server_port=port,
                          username=username,
                          password=password,
                          tenant_name=tenant)

    def create_network(self, vn_name, mask=24):
        ''' Create virtual network using VNC api '''
        cidr = get_randmon_cidr(mask=mask)
        self.id.vn_obj[vn_name] = VirtualNetwork(vn_name)
        self.id.vn_obj[vn_name].add_network_ipam(NetworkIpam(),
                             VnSubnetsType([IpamSubnetType(
                             subnet=SubnetType(cidr, mask))]))
        self.id.vn_uuid[vn_name] = self.vnc.virtual_network_create(self.id.vn_obj[vn_name])
        print self.vnc.virtual_network_read(id = self.id.vn_uuid[vn_name])
        print self.vnc.virtual_networks_list()

def get_randmon_cidr(mask=16):
    ''' Generate random non-overlapping cidr '''
    global alloc_addr_list
    address = socket.inet_ntop(socket.AF_INET,
                               struct.pack('>I',
                               random.randint(2**24, 2**32 - 2**29 - 1)))
    address = str(IPNetwork(address+'/'+str(mask)).network)
    if address.startswith('169.254') or address in alloc_addr_list:
        get_randmon_cidr()
    alloc_addr_list.append(address)
    return address+'/'+str(mask)

def parse_cli(args):
    '''Define and Parser arguments for the script'''
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--api_server_ip',
                        action='store',
                        default='127.0.0.1',
                        help='API Server IP [127.0.0.1]')
    parser.add_argument('--keystone_ip',
                        action='store',
                        default='127.0.0.1',
                        help='Keystone IP [127.0.0.1]')
    parser.add_argument('--api_server_port',
                        action='store',
                        default='8082',
                        help='API Server Port [8082]')
    parser.add_argument('--admin_username',
                        action='store',
                        default='admin',
                        help='Admin user name [admin]')
    parser.add_argument('--admin_password',
                        action='store',
                        default='contrail123',
                        help="Admin user's password [contrail123]")
    parser.add_argument('--admin_tenant',
                        action='store',
                        default='admin',
                        help='Admin Tenant name [admin]')
    parser.add_argument('--username',
                        action='store',
                        default='admin',
                        help='Tenant user name [admin]')
    parser.add_argument('--password',
                        action='store',
                        default='contrail123',
                        help="Tenant user's password [contrail123]")
    parser.add_argument('--tenant',
                        action='store',
                        default='admin',
                        help='Tenant name [admin]')
    parser.add_argument('--n_process',
                        action='store',
                        default='1', type=int,
                        help='No of Parallel instances to run [1]')
    parser.add_argument('--image_id',
                        action='store',
                        default=None,
                        help='Image ID [None]')
    parser.add_argument('--n_vns',
                        action='store',
                        default='0', type=int,
                        help='No of Vns to create [0]')
    parser.add_argument('--n_ports',
                        action='store',
                        default='0', type=int,
                        help='No of Ports to create [0]')
    parser.add_argument('--n_sgs',
                        action='store',
                        default='0', type=int,
                        help='No of Security Groups to create [0]')
    parser.add_argument('--n_sg_rules',
                        action='store',
                        default='0', type=int,
                        help='No of Security Group Rules to create [0]')
    parser.add_argument('--n_routers',
                        action='store',
                        default='0', type=int,
                        help='No of Routers to create [0]')
    parser.add_argument('--n_vms',
                        action='store',
                        default='0', type=int,
                        help='No of VMs to create [0]')
    parser.add_argument('--n_fips',
                        action='store',
                        default='0', type=int,
                        help='No of Floating-IPs to create [0]')
    parser.add_argument('--vnc',
                        action='store_true',
                        help='Use VNC client to config vn, sg, policies [False]')
    parser.add_argument('--cleanup',
                        action='store_true',
                        help='Cleanup the created objects [False]')

    pargs = parser.parse_args(args)
    return pargs

def random_string(prefix):
    return prefix+''.join(random.choice(string.hexdigits) for _ in range(8))

def sig_handler(_signo, _stack_frame):
    raise KeyboardInterrupt

def main():
    signal.signal(signal.SIGTERM, sig_handler)
    pargs = parse_cli(sys.argv[1:])
    obj = config(pargs)
    obj.verify()
    obj.pre_conf()
    obj.run()

if __name__ == '__main__':
    main()

