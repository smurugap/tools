import os
import sys
import time
import uuid
import yaml
import argparse
from concurrent import futures
from keystoneclient.v2_0 import client as ks_client
from novaclient import client as nova_client
from vnc_api.vnc_api import *
import MySQLdb
from datetime import datetime
import logging

OS_USERNAME='admin'
OS_PASSWORD='contrail123'
OS_DOMAIN_NAME='default-domain'
OS_AUTH_URL='http://127.0.0.1:5000/v2.0'
CONTRAIL_API_IP='127.0.0.1'
CONTRAIL_API_PORT='8082'
DB_NOVA_PASSWD='c0ntrail123'
DB_HOST='127.0.0.1'
ADMIN_TENANT='admin'
ADMIN_USERID='903db2adc51647e1ae2bd3a085ea91d0'
ADMIN_ROLEID='cb2a02eadb194ebe966b426373c2d9b8'
FIP_POOL_FQNAME='default-domain:demo:ext-net:public'
log = True

def time_taken(f):
    def wrapper(*args, **kwargs):
        start_time = datetime.now()
        msg = 'Time taken for op %s'%f.__name__
        tenant = None
        name = kwargs.get('name', None)
        if args and isinstance(args[0], PerTenant):
            tenant = getattr(args[0], 'tenant_name', None)
        if name:
            msg = msg + ', name %s,'%name
        elif len(args) > 1:
            msg = msg + ', ' + str(args[1])
        msg = msg + ', tenant %s,'%tenant if tenant else msg
        ret = f(*args, **kwargs)
        print msg, str(datetime.now() - start_time)
        return ret
    return wrapper

from copy_reg import pickle
from types import MethodType

def _pickle_method(method):
    func_name = method.im_func.__name__
    obj = method.im_self
    cls = method.im_class
    return _unpickle_method, (func_name, obj, cls)

def _unpickle_method(func_name, obj, cls):
    for cls in cls.mro():
        try:
            func = cls.__dict__[func_name]
        except KeyError:
            pass
        else:
            break
    return func.__get__(obj, cls)
pickle(MethodType, _pickle_method, _unpickle_method)

class Client(object):
    def __init__(self, tenant_name, auth_token=None):
        self.tenant_name = tenant_name
        if not auth_token:
            self.keystone = ks_client.Client(username=OS_USERNAME,
                                             password=OS_PASSWORD,
                                             tenant_name=self.tenant_name,
                                             auth_url=OS_AUTH_URL)
            auth_token = self.keystone.auth_token
            self.tenant_id = self.keystone.auth_tenant_id
        self.auth_token = auth_token

    @property
    def vnc_api_h(self):
        if not getattr(self, '_vnc_api_h', None):
            self._vnc_api_h = VncApi(api_server_host=CONTRAIL_API_IP,
                                     api_server_port=CONTRAIL_API_PORT,
                                     auth_token=self.auth_token)
        return self._vnc_api_h

    @property
    def nova_h(self):
        if not getattr(self, '_nova_h', None):
            self._nova_h = nova_client.Client('2', auth_token=self.auth_token,
                                              username=OS_USERNAME,
                                              api_key=OS_PASSWORD,
                                              project_id=self.tenant_name,
                                              auth_url=OS_AUTH_URL)
        return self._nova_h

    @property
    def db_h(self):
        if not getattr(self, '_db_h', None):
            self._db_h = MySQLdb.connect(user='nova', passwd=DB_NOVA_PASSWD,
                                         host=DB_HOST, db='nova')
            self.cursor = self._db_h.cursor(MySQLdb.cursors.DictCursor)
        return self._db_h

    def query_db(self, query):
        self.db_h.rollback()
        self.cursor.execute(query)
        return self.cursor.fetchall()

    #@time_taken
    def create_tenant(self, name):
        tenant = self.keystone.tenants.create(name)
        self.keystone.roles.add_user_role(tenant=tenant.id,
                                          user=ADMIN_USERID,
                                          role=ADMIN_ROLEID)

    #@time_taken
    def create_network(self, name, cidr, properties=None):
        network, mask = cidr.split('/')
        fq_name = [OS_DOMAIN_NAME, self.tenant_name, name]
        ipam_subnet_type = IpamSubnetType(subnet=SubnetType(network, int(mask)))
        vn_obj = VirtualNetwork(name, parent_type='project', fq_name=fq_name)
        if properties:
            if properties.get('gateway'):
                ipam_subnet_type.default_gateway = properties.get('gateway')
            if properties.get('flood_unknown_unicast') == True:
                vn_obj.flood_unknown_unicast = True
            vn_prop = VirtualNetworkType()
            if properties.get('forwarding_mode'):
                vn_prop.set_forwarding_mode(properties.get('forwarding_mode'))
            vn_obj.set_virtual_network_properties(vn_prop)
        vn_obj.add_network_ipam(NetworkIpam(), VnSubnetsType([ipam_subnet_type]))
        self.vnc_api_h.virtual_network_create(vn_obj)
        return vn_obj

    #@time_taken
    def delete_network(self, name):
        fq_name = [OS_DOMAIN_NAME, self.tenant_name, name]
        try:
            self.vnc_api_h.virtual_network_delete(fq_name=fq_name)
        except NoIdError:
            pass
    #@time_taken
    def create_port(self, name, vn_obj, sg_obj):
        fq_name = [OS_DOMAIN_NAME, self.tenant_name, name]
        iip_name = '__'.join(fq_name)
        port_obj = VirtualMachineInterface(name, parent_type='project', fq_name=fq_name)
        port_id = port_obj.uuid = str(uuid.uuid4())
        port_obj.add_virtual_network(vn_obj)
        port_obj.add_security_group(sg_obj)
        self.vnc_api_h.virtual_machine_interface_create(port_obj)

        iip_obj = InstanceIp(name=iip_name)
        iip_obj.uuid = iip_id = str(uuid.uuid4())
        iip_obj.add_virtual_network(vn_obj)
        iip_obj.add_virtual_machine_interface(port_obj)
        self.vnc_api_h.instance_ip_create(iip_obj)
        return (port_obj, iip_obj)

    #@time_taken
    def delete_port(self, name):
        fq_name = [OS_DOMAIN_NAME, self.tenant_name, name]
        iip_name = '__'.join(fq_name)
        try:
            self.vnc_api_h.instance_ip_delete(fq_name=[iip_name])
        except NoIdError:
            pass
        try:
            self.vnc_api_h.virtual_machine_interface_delete(fq_name=fq_name)
        except NoIdError:
            pass

    #@time_taken
    def get_iip(self, uuid):
        return self.vnc_api_h.instance_ip_read(id=uuid)

    #@time_taken
    def create_fip(self, name, port_obj, iip_obj, project_obj):
        #ip_address = self.vnc_api_h.instance_ip_read(id=iip_obj.uuid).get_instance_ip_address()
        fq_name = FIP_POOL_FQNAME.split(':') + [name]
        fip_obj = FloatingIp(name=name, parent_type='floating-ip-pool', fq_name=fq_name)
        fip_id = fip_obj.uuid = str(uuid.uuid4())
        fip_obj.add_virtual_machine_interface(port_obj)
        #fip_obj.set_floating_ip_fixed_ip_address(ip_address)
        fip_obj.add_project(project_obj)
        self.vnc_api_h.floating_ip_create(fip_obj)
        return fip_obj

    #@time_taken
    def delete_fip(self, name):
        fq_name = FIP_POOL_FQNAME.split(":") + [name]
        try:
            self.vnc_api_h.floating_ip_delete(fq_name=fq_name)
        except:
            pass

    #@time_taken
    def launch_vm(self, name, ports, flavor, image, metadata=None, personality=None):
        nics = [{'port-id': port} for port in ports]
        files = None
        if personality:
            files = {k: open(v, 'r') for k,v in personality.iteritems()}
        if metadata:
            for k in metadata.keys():
                metadata[k] = str(metadata[k])
        vm_obj = self.nova_h.servers.create(name=name, flavor=flavor,
                                            image=image, nics=nics,
                                            meta=metadata, files=files,
                                            config_drive=True if metadata else None)
        return vm_obj

    #@time_taken
    def delete_vm(self, name):
        query = 'select uuid from instances where display_name="%s" and deleted=0;'%name
        resp = self.query_db(query)
        if not resp or len(resp) < 1:
            return
        vm_id = resp[0]['uuid']
        self.nova_h.servers.delete(vm_id)

    #@time_taken
    def get_network(self, vn_id=None, name=None):
        if name:
            fq_name = [OS_DOMAIN_NAME, self.tenant_name, name]
            return self.vnc_api_h.virtual_network_read(fq_name=fq_name)
    def get_network(self, vn_id):
        return self.vnc_api_h.virtual_network_read(id=vn_id)

    #@time_taken
    def get_project(self, project_id):
        return self.vnc_api_h.project_read(id=project_id)

    #@time_taken
    def get_security_group(self, sg_id):
        return self.vnc_api_h.security_group_read(id=sg_id)

class PerVM(object):
    def __init__(self, name, tenant_name, auth_token, tenant_obj=None,
                 port_objs=None, tenant_sg_obj=None, image_id=None,
                 flavor_id=None, vn_objs=None, private_networks=None,
                 ctrl_network=None, fabric_network=None,
                 metadata=None, personality=None):
        self.name = name
        self.fip_name = name + '_fip'
        self.t_port_name = name + '_tenant_port'
        self.c_port_name = name + '_ctrl_port'
        self.f_port_name = name + '_fabric_port'
        self.tenant_name = tenant_name
        self.tenant_obj = tenant_obj
        self.port_objs = port_objs
        self.tenant_sg_obj = tenant_sg_obj
        self.vn_objs = vn_objs
        self.image_id = image_id
        self.flavor_id = flavor_id
        self.private_networks = private_networks
        self.ctrl_network = ctrl_network
        self.fabric_network = fabric_network
        self.metadata = metadata
        self.personality = personality
        self.client_h = Client(self.tenant_name, auth_token)
        if log:
            logging.basicConfig(filename=name+'.log', level=logging.DEBUG)
            self.log = logging.getLogger(name)

    def delete_tenant_port(self):
        self.client_h.delete_fip(self.fip_name)
        self.client_h.delete_port(self.t_port_name)

    def create_private_ports(self):
        ports = list()
        for priv_vn in self.private_networks:
            vn_obj = self.vn_objs[priv_vn]
            p_port_name = self.name + '_' + priv_vn + '_priv_port'
            (port_obj, iip_obj) = self.client_h.create_port(p_port_name,
                                            vn_obj, self.tenant_sg_obj)
            ports.append(port_obj.uuid)
        return ports

    def delete_private_ports(self):
        ports = list()
        for priv_vn in self.private_networks:
            p_port_name = self.name + '_' + priv_vn + '_priv_port'
            self.client_h.delete_port(p_port_name)

    def create_ctrl_port(self):
        ctrl_vn_obj = self.vn_objs[self.ctrl_network]
        (port_obj, iip_obj) = self.client_h.create_port(self.c_port_name,
                                            ctrl_vn_obj, self.tenant_sg_obj)
        return port_obj.uuid

    def delete_ctrl_port(self):
        self.client_h.delete_port(self.c_port_name)

    def create_fabric_port(self):
        fabric_vn_obj = self.vn_objs[self.fabric_network]
        (port_obj, iip_obj) = self.client_h.create_port(self.f_port_name,
                                            fabric_vn_obj, self.tenant_sg_obj)
        return port_obj.uuid

    def delete_fabric_port(self):
        self.client_h.delete_port(self.f_port_name)

    def create_topology(self):
        try:
            t_port_id = self.port_objs[self.name].uuid
            nics = [t_port_id]
            if self.ctrl_network:
                c_port_id = self.create_ctrl_port()
                nics.append(c_port_id)
            if self.fabric_network:
                f_port_id = self.create_fabric_port()
                nics.append(f_port_id)
            if self.private_networks:
                p_port_ids = self.create_private_ports()
                nics.extend(p_port_ids)
            vm_obj = self.client_h.launch_vm(self.name, nics,
                                             self.flavor_id, self.image_id,
                                             metadata=self.metadata,
                                             personality=self.personality)
            return vm_obj.id
        except:
            if log:
                self.log.exception('Exception for instance'+self.name)

    def delete_topology(self):
        self.client_h.delete_vm(self.name)
        self.delete_tenant_port()
        if self.ctrl_network:
            self.delete_ctrl_port()
        if self.fabric_network:
            self.delete_fabric_port()
        if self.private_networks:
            self.delete_private_ports()

class PerTenant(object):
    def __init__(self, tenant_name, tenant_vn_name, instances, networks):
        self.tenant_name = tenant_name
        self.tenant_vn_name = tenant_vn_name
        self.instances = instances
        self.networks = networks
        self.vn_objs = dict()
        self.port_objs = dict()
        self.iip_objs = dict()
        self.vm_ids = list()
        self.active_vm_ids = list()

    def launch_and_verify(self):
        self.launch_topo()
        self.verify_active()

    @property
    def client_h(self):
        if not getattr(self, '_client_h', None):
            self._client_h = Client(self.tenant_name)
        return self._client_h

    def pre_conf(self):
        #admin_client = Client(ADMIN_TENANT)
        #admin_client.create_tenant(self.tenant_name)
        #self.client_h = Client(self.tenant_name)
        self.tenant_id = self.client_h.tenant_id
        self.tenant_obj = self.client_h.get_project(str(uuid.UUID(self.tenant_id)))
        for vn_name, vn_prop in self.networks.iteritems():
            self.vn_objs[vn_name] = self.client_h.create_network(
                                                 self.tenant_name+'_'+vn_name,
                                                 cidr=vn_prop['cidr'],
                                                 properties=vn_prop)
        self.tenant_vn_obj = self.client_h.get_network(name=self.tenant_vn_name)
        sg_id = self.tenant_obj.get_security_groups()[0]['uuid']
        self.tenant_sg_obj = self.client_h.get_security_group(sg_id)
        for instance in self.instances:
            inst_name = self.get_instance_name(instance)
            fip_name = inst_name + '_fip'
            t_port_name = inst_name + '_tenant_port'
            (port_obj, iip_obj) = self.client_h.create_port(t_port_name,
                                                            self.tenant_vn_obj,
                                                            self.tenant_sg_obj)
            fip_obj = self.client_h.create_fip(fip_name,
                                               port_obj,
                                               iip_obj,
                                               self.tenant_obj)
            self.port_objs[inst_name] = port_obj
            self.iip_objs[inst_name] = iip_obj

    def get_instance_name(self, instance):
        name = instance['name'] if isinstance(instance, dict) else instance
        return '.'.join([self.tenant_name, name])

    def update_meta_refs(self):
        for instance in self.instances:
            metaref = dict()
            for metakey, metaval in instance['metadata_refs'].iteritems():
                if metakey.lower() == 're0_ip' or metakey.lower() == 're1_ip':
                    iip_obj = self.iip_objs[self.get_instance_name(metaval)]
                    if not iip_obj.get_instance_ip_address():
                        iip_obj = self.client_h.get_iip(iip_obj.uuid)
                        self.iip_objs[self.get_instance_name(metaval)] = iip_obj
                    metaval = iip_obj.get_instance_ip_address()
                metaref[metakey] = metaval
            if 'metadata' not in instance:
                instance['metadata'] = dict()
            instance['metadata'].update(metaref)

    def launch_topo_wrapper(self):
        return self.launch_topo()

    @time_taken
    def launch_topo(self):
        self.pre_conf()
        for instance in self.instances:
            inst_name = self.get_instance_name(instance)
            self.update_meta_refs()
            vm_id = PerVM(name=inst_name,
                          tenant_name=self.tenant_name,
                          auth_token=self.client_h.auth_token,
                          tenant_obj=self.tenant_obj,
                          port_objs=self.port_objs,
                          tenant_sg_obj=self.tenant_sg_obj,
                          vn_objs=self.vn_objs,
                          image_id=instance['image'],
                          flavor_id=instance['flavor'],
                          private_networks=instance.get('private_networks'),
                          ctrl_network=instance.get('ctrl_network'),
                          fabric_network=instance.get('fabric_network'),
                          metadata=instance.get('metadata'),
                          personality=instance.get('personality')).create_topology()
            if vm_id:
                self.vm_ids.append(vm_id)

    def construct_query(self):
        vm_ids = set(self.vm_ids) - set(self.active_vm_ids)
        vms = ['uuid="%s"'%vm_id for vm_id in vm_ids]
        return 'select vm_state,power_state,uuid from instances where %s;'%(' or '.join(vms))

    def verify_active(self):
        while True:
            vm_states = self.client_h.query_db(self.construct_query())
            for vm_state in vm_states:
                if vm_state['vm_state'] == 'active' and int(vm_state['power_state']) == 1:
                    self.active_vm_ids.append(vm_state['uuid'])
            if set(self.vm_ids) - set(self.active_vm_ids):
                time.sleep(5)
            else:
                break

    @time_taken
    def verify_active_count(self, exp_count):
        while True:
            query = "select count(id) from instances where deleted=0 and display_name LIKE 'cumulus-test%' and vm_state='active' and power_state=1;"
            response = self.client_h.query_db(query)[0]
            if int(response['count(id)']) == (exp_count):
                break
            print 'exp count %s, actual count %s'%(exp_count, response['count(id)'])
            time.sleep(5)

    def delete_wrapper(self):
        return self.delete_topo()

    @time_taken
    def delete_topo(self):
        for instance in self.instances:
            inst_name = self.get_instance_name(instance)
            PerVM(name=inst_name, tenant_name=self.tenant_name,
                  private_networks=instance.get('private_networks'),
                  ctrl_network=instance.get('ctrl_network'),
                  fabric_network=instance.get('fabric_network'),
                  auth_token=self.client_h.auth_token).delete_topology()
        for vn_name, vn_prop in self.networks.iteritems():
            self.client_h.delete_network(self.tenant_name+'_'+vn_name)

def main(templates, oper):
    pobjs = list()
    for template in templates:
        with open(template, 'r') as fd:
            try:
                yargs = yaml.load(fd)
            except yaml.YAMLError as exc:
                print exc
                raise
        pobjs.append(PerTenant(yargs['tenant_name'], yargs['tenant_vn_name'],
                               yargs['instances'], yargs['networks']))
    with futures.ProcessPoolExecutor(max_workers=64) as executor:
#        pobjs[0].launch_topo()
#        fs = [executor.submit(pobj.launch_topo_wrapper) for pobj in pobjs]
        if oper.lower().startswith('del'):
            pobjs[0].delete_wrapper()
            #fs = [executor.submit(pobj.delete_wrapper) for pobj in pobjs]
        elif oper.lower() == 'add':
            pobjs[0].launch_and_verify()
            #fs = [executor.submit(pobj.launch_and_verify) for pobj in pobjs]
        else:
            raise Exception()
        print 'waiting for all clients to complete'
#        futures.wait(fs, timeout=3600, return_when=futures.ALL_COMPLETED)
#    pobjs[0].verify_active_count(exp_count=len(pobjs)*len(yargs['instances']))

def parse_cli(args):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-t', '--templates', required=True, metavar="FILE",
                        nargs='+', help='location of the yaml template files')
    parser.add_argument('-o', '--oper', default='add',
                        help='Operation to perform (add/delete)')
    pargs = parser.parse_args(args)
    return pargs

if __name__ == '__main__':
    pargs = parse_cli(sys.argv[1:])
    main(pargs.templates, pargs.oper)
