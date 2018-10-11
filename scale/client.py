import os
import shlex
from keystoneauth1 import identity, session
from keystoneclient import client
from vnc_api.vnc_api import *
import logging
import subprocess
import socket
import struct
import random
from netaddr import *
from collections import defaultdict
alloc_addr_list = list()

API_SERVER_IP = os.getenv('API_SERVER_IP', '127.0.0.1')
OS_AUTH_URL = os.getenv('OS_AUTH_URL', 'http://127.0.0.1:5000/v2.0')
OS_USERNAME = os.getenv('OS_USERNAME', 'admin')
OS_PASSWORD = os.getenv('OS_PASSWORD', 'contrail123')
ADMIN_TENANT = os.getenv('OS_TENANT_NAME') or os.getenv('OS_PROJECT_NAME') or 'admin'
OS_DOMAIN_NAME = os.getenv('OS_DOMAIN_NAME', 'Default')
if OS_DOMAIN_NAME == 'Default':
   CONTRAIL_DOMAIN_NAME = 'default-domain'
CONTRAIL_API_PORT = '8082'
ADMIN_ROLE = 'admin'

class Client(object):
    def __init__(self, project_name):
        self.project_name = project_name
        self.session = self.get_session()
        self.keystone = self.get_client()
        self._set_auth_vars()
        self.vn_objs = dict()
        self.prouter_objs = dict()
        self.vmi_objs = dict()

    def get_session(self, version='3'):
        if version == '2':
           auth = identity.v2.Password(auth_url=OS_AUTH_URL,
                                       username=OS_USERNAME,
                                       password=OS_PASSWORD,
                                       tenant_name=self.project_name)
        elif version == '3':
           auth = identity.v3.Password(auth_url=OS_AUTH_URL,
                                       username=OS_USERNAME,
                                       password=OS_PASSWORD,
                                       project_name=self.project_name,
                                       user_domain_name=OS_DOMAIN_NAME,
                                       project_domain_name=OS_DOMAIN_NAME)
        return session.Session(auth=auth, verify=False)

    def get_client(self, scope='domain'):
        return client.Client(version='3', session=self.session,
                             auth_url=OS_AUTH_URL)

    def _set_auth_vars(self):
        '''
        Set auth_protocol, auth_ip, auth_port from self.auth_url
        '''
        match = re.match(r'(.*?)://(.*?):([\d]+).*$', OS_AUTH_URL, re.M|re.I)
        if match:
            self.auth_protocol = match.group(1)
            self.auth_host = match.group(2)
            self.auth_port = match.group(3)
        if 'v2' in OS_AUTH_URL:
            self.authn_url = '/v2.0/tokens'
        else:
            self.authn_url = '/v3/auth/tokens'

    @property
    def vnc_api_h(self):
        if not getattr(self, '_vnc_api_h', None):
            self._vnc_api_h = VncApi(api_server_host=API_SERVER_IP,
                                     api_server_port=CONTRAIL_API_PORT,
                                     username=OS_USERNAME,
                                     password=OS_PASSWORD,
                                     tenant_name=self.project_name,
                                     domain_name=OS_DOMAIN_NAME,
                                     auth_host=self.auth_host,
                                     auth_port=self.auth_port,
                                     auth_url=self.authn_url
                                     )
        return self._vnc_api_h

    def get_user(self, username):
        users = self.keystone.users.list()
        for user in users:
            if user.name == username:
                return user
        raise Exception('User %s not found'%username)

    def get_role(self, rolename):
        roles = self.keystone.roles.list()
        for role in roles:
            if role.name == rolename:
                return role
        raise Exception('role %s not found'%rolename)

    def find_domain(self, domain_name):
        return self.keystone.domains.find(name=domain_name)

    def create_tenant(self, name):
        tenant = self.keystone.projects.create(name=name,
                 domain=self.find_domain(OS_DOMAIN_NAME))
        self.keystone.roles.grant(self.get_role(ADMIN_ROLE),
                                  project=tenant,
                                  user=self.get_user(OS_USERNAME),
                                  group=None)
        return tenant

    def delete_tenant(self, name):
        obj = self.keystone.projects.find(name=name)
        self.keystone.projects.delete(obj)

    def enable_vxlan_routing(self, **kwargs):
        obj = self.get_project(**kwargs)
        obj.set_vxlan_routing(True)
        self.vnc_api_h.project_update(obj)

    def create_network(self, name, cidr=None):
        cidr = get_random_cidr(mask=28) if not cidr else cidr
        network, mask = cidr.split('/')
        fq_name = [CONTRAIL_DOMAIN_NAME, self.project_name, name]
        ipam_subnet_type = IpamSubnetType(subnet=SubnetType(network, int(mask)),
                                          addr_from_start=True)
        vn_obj = VirtualNetwork(name, parent_type='project', fq_name=fq_name)
        vn_obj.add_network_ipam(NetworkIpam(), VnSubnetsType([ipam_subnet_type]))
        self.vnc_api_h.virtual_network_create(vn_obj)
        self.vn_objs[name] = vn_obj
        return vn_obj

    def delete_network(self, name):
        fq_name = [CONTRAIL_DOMAIN_NAME, self.project_name, name]
        try:
            self.vnc_api_h.virtual_network_delete(fq_name=fq_name)
        except NoIdError:
            pass

    def create_port(self, name, vn_name):
        fq_name = [CONTRAIL_DOMAIN_NAME, self.project_name, name]
        port_obj = VirtualMachineInterface(name, parent_type='project',
                                           fq_name=fq_name)
        port_obj.add_virtual_network(self.get_vn_obj(vn_name))
        self.vnc_api_h.virtual_machine_interface_create(port_obj)

        iip_obj = InstanceIp(name=name)
        iip_obj.add_virtual_network(self.get_vn_obj(vn_name))
        iip_obj.add_virtual_machine_interface(port_obj)
        self.vnc_api_h.instance_ip_create(iip_obj)
        self.vmi_objs[name] = port_obj
        return (port_obj, iip_obj)

    def delete_port(self, name):
        fq_name = [CONTRAIL_DOMAIN_NAME, self.project_name, name]
        try:
            self.vnc_api_h.instance_ip_delete(fq_name=[name])
        except NoIdError:
            pass
        try:
            self.vnc_api_h.virtual_machine_interface_delete(fq_name=fq_name)
        except NoIdError:
            pass

    def create_lif(self, prouter, pif_name, vlan=None, unit=None, vmi=None):
        unit = vlan if vlan and unit is None else (unit or 0)
        lif_name = pif_name+'.'+str(unit)
        pif_fqname = ['default-global-system-config', prouter, pif_name.replace(':', '_')]
        fq_name = pif_fqname+[lif_name.replace(':', '_')]
        obj = LogicalInterface(name=fq_name[-1],
                               parent_type='physical-interface',
                               fq_name=fq_name,
                               display_name=lif_name)
        if vlan is not None:
            obj.set_logical_interface_vlan_tag(vlan)
        if vmi:
            obj.add_virtual_machine_interface(self.get_vmi_obj(vmi))
        return self.vnc_api_h.logical_interface_create(obj)

    def delete_lif(self, prouter, pif_name, vlan=None, unit=None):
        unit = vlan if vlan and unit is None else (unit or 0)
        lif_name = pif_name+'.'+str(unit)
        pif_fqname = ['default-global-system-config', prouter, pif_name.replace(':', '_')]
        fq_name = pif_fqname+[lif_name.replace(':', '_')]
        try:
            self.vnc_api_h.logical_interface_delete(fq_name=fq_name)
        except NoIdError:
            pass

    def read_physical_router(self, name):
        fq_name = ['default-global-system-config', name]
        return self.vnc_api_h.physical_router_read(fq_name=fq_name)

    def get_prouter_obj(self, name):
        if name not in self.prouter_objs:
            self.prouter_objs[name] = self.read_physical_router(name)
        return self.prouter_objs[name]

    def get_vn_obj(self, name):
        return self.vn_objs[name]

    def get_vmi_obj(self, name):
        return self.vmi_objs[name]

    def create_logical_router(self, name, vni=None, networks=None, spines=None):
        vni = str(vni) if vni else None
        fq_name = [CONTRAIL_DOMAIN_NAME, self.project_name, name]
        obj = LogicalRouter(name=name, fq_name=fq_name, parent_type='project',
                            vxlan_network_identifier=vni)
        for spine in spines or []:
            obj.add_physical_router(self.get_prouter_obj(spine))
        for network in networks or []:
            port_obj, iip_obj = self.create_port(name+'-'+network, network)
            obj.add_virtual_machine_interface(port_obj)
        self.vnc_api_h.logical_router_create(obj)
        return obj

    def delete_logical_router(self, name, vns=None):
        fq_name = [CONTRAIL_DOMAIN_NAME, self.project_name, name]
        if vns:
            try:
                obj = self.vnc_api_h.logical_router_read(fq_name=fq_name)
                obj.set_virtual_machine_interface_list([])
                self.vnc_api_h.logical_router_update(obj)
            except NoIdError:
                pass
            for vn_name in vns:
                self.delete_port(name+'-'+vn_name)
        try:
            self.vnc_api_h.logical_router_delete(fq_name=fq_name)
        except NoIdError:
            pass

    def get_project(self, **kwargs):
        return self.vnc_api_h.project_read(**kwargs)

    @property
    def project_id(self):
        if not getattr(self, '_project_id', None):
            project_obj = self.get_project(
                fq_name=[CONTRAIL_DOMAIN_NAME, self.project_name])
            self._project_id = project_obj.uuid.replace('-','')
        return self._project_id

def get_random_cidr(mask=16):
    ''' Generate random non-overlapping cidr '''
    global alloc_addr_list
    address = socket.inet_ntop(socket.AF_INET,
                               struct.pack('>I',
                               random.randint(2**24, 2**32 - 2**29 - 1)))
    address = str(IPNetwork(address+'/'+str(mask)).network)
    if address.startswith('169.254') or address in alloc_addr_list:
        cidr = get_randmon_cidr()
    else:
        alloc_addr_list.append(address)
        cidr = address+'/'+str(mask)
    return cidr

