import os
import sys
import time
import uuid
import yaml
import argparse
import logging
from client import *
from collections import defaultdict

API_SERVER_IP = os.getenv('API_SERVER_IP', '127.0.0.1')

class PerTenant(object):
    def __init__(self, project_name, networks=None,
                 logical_routers=None, spines=None, bms=None):
        self.project_name = project_name
        self.networks = networks
        self.logical_routers = logical_routers
        self.spines = spines
        self.bms = bms
        self.lr_vn_mapping = defaultdict(list)
        self.bms_vn_mapping = defaultdict(list)

    @property
    def client_h(self):
        if not getattr(self, '_client_h', None):
            self._client_h = Client(self.project_name)
        return self._client_h

    def setup(self):
        admin_client = Client(ADMIN_TENANT)
        tenant = admin_client.create_tenant(self.project_name)
        admin_client.enable_vxlan_routing(id=str(uuid.UUID(tenant.id)))

    def wait_till_project_objs_delete(self):
        retry = 0
        max_retry = 20
        while True:
            tenant_obj = self.client_h.get_project(
                fq_name=[CONTRAIL_DOMAIN_NAME, self.project_name])
            vns = tenant_obj.get_virtual_networks()
            vmis = tenant_obj.get_virtual_machine_interfaces()
            sgs = tenant_obj.get_security_groups()
            if vns or vmis or (sgs and len(sgs) > 1):
                if retry < max_retry:
                    retry += 1
                    time.sleep(15)
                    continue
                return False
            return True

    def teardown(self):
        assert self.wait_till_project_objs_delete(), 'Project %s still has objs'%self.project_name
        admin_client = Client(ADMIN_TENANT)
        admin_client.delete_tenant(self.project_name)

    def get_name(self, suffix, index):
        return '.'.join([self.project_name, suffix, str(index)])

    def create_networks(self):
        for vn_name, prop in self.networks.iteritems():
            for index in range(0, prop.get('count', 1)):
                name = self.get_name(vn_name, index)
                self.client_h.create_network(name)
                for lr in prop.get('lr') or []:
                    self.lr_vn_mapping[lr].append(name)
                for bms in prop.get('bms') or []:
                    self.bms_vn_mapping[bms].append(name)

    def delete_networks(self):
        for vn_name, prop in self.networks.iteritems():
            for index in range(0, prop.get('count', 1)):
                name = self.get_name(vn_name, index)
                self.client_h.delete_network(name)

    def create_logical_routers(self):
        lrs = set(self.logical_routers.keys() + self.lr_vn_mapping.keys())
        for lr_name in lrs:
            name = self.get_name(lr_name, 0)
            vni = self.logical_routers.get(lr_name, {}).get('vni')
            networks = self.lr_vn_mapping.get(lr_name)
            self.client_h.create_logical_router(name, vni, networks, self.spines)

    def delete_logical_routers(self):
        lr_vn_mapping = defaultdict(list)
        for vn_name, prop in self.networks.iteritems():
            for index in range(0, prop.get('count', 1)):
                name = self.get_name(vn_name, index)
                for lr in prop.get('lr') or []:
                    lr_vn_mapping[lr].append(name)
        lrs = set(self.logical_routers.keys() + lr_vn_mapping.keys())
        for lr_name in lrs:
            name = self.get_name(lr_name, 0)
            networks = lr_vn_mapping.get(lr_name)
            self.client_h.delete_logical_router(name, networks)

    def create_bms(self, name, vn_name, interfaces, vlan=None):
        self.client_h.create_port(name, vn_name)
        for interface in interfaces:
            self.client_h.create_lif(prouter=interface['tor'],
                                     pif_name=interface['pif'],
                                     unit=vlan,
                                     vlan=vlan,
                                     vmi=name)

    def create_bms_instances(self):
        for bms, vn_names in self.bms_vn_mapping.iteritems():
            if bms not in self.bms:
                raise Exception('BMS info not found for %s'%bms)
            for index, vn_name in enumerate(vn_names):
                bms_name = self.get_name(bms, index)
                self.create_bms(bms_name, vn_name,
                                self.bms[bms]['interfaces'],
                                vlan=(index+5))

    def delete_bms(self, name, vn_name, interfaces, vlan=None):
        for interface in interfaces:
            self.client_h.delete_lif(prouter=interface['tor'],
                                     pif_name=interface['pif'],
                                     unit=vlan,
                                     vlan=vlan)
        self.client_h.delete_port(name)

    def delete_bms_instances(self):
        bms_vn_mapping = defaultdict(list)
        for vn_name, prop in self.networks.iteritems():
            for index in range(0, prop.get('count', 1)):
                name = self.get_name(vn_name, index)
                for bms in prop.get('bms') or []:
                    bms_vn_mapping[bms].append(name)
        for bms, vn_names in bms_vn_mapping.iteritems():
            if bms not in self.bms:
                raise Exception('BMS info not found for %s'%bms)
            for index, vn_name in enumerate(vn_names):
                bms_name = self.get_name(bms, index)
                self.delete_bms(bms_name, vn_name,
                                self.bms[bms]['interfaces'],
                                vlan=(index+5))

    def create(self):
        self.setup()
        self.create_networks()
        self.create_logical_routers()
        self.create_bms_instances()

    def delete(self):
        self.delete_bms_instances()
        self.delete_logical_routers()
        self.delete_networks()
        self.teardown()

def read_yaml(filename):
    with open(filename, 'r') as fd:
        yargs = yaml.load(fd)
    return yargs

def create_delete_topology(topology, oper):
    yargs = read_yaml(topology)
    for project, config in yargs.get('projects', {}).iteritems():
        for index in range(0, config.get('count', 1)):
            project_name = project + '.' + str(index)
            pobj = PerTenant(project_name,
                             networks=config.get('networks'),
                             logical_routers=config.get('logical_routers'),
                             bms=yargs.get('bms'),
                             spines=yargs.get('spines'))
            if oper.lower().startswith('del'):
                pobj.delete()
            elif oper.lower() == 'add':
                pobj.create()
            else:
                raise Exception()

def parse_cli(args):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-t', '--topology', required=True, metavar="FILE",
                        help='location of the topology file')
    parser.add_argument('-o', '--oper', default='add',
                        help='operation to perform (add/delete)')
    pargs = parser.parse_args(args)
    return pargs

if __name__ == '__main__':
    pargs = parse_cli(sys.argv[1:])
    create_delete_topology(pargs.topology, pargs.oper)
