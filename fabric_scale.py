import random
import socket
import struct
import uuid
from netaddr import *

from vnc_api.vnc_api import *
import yaml
import argparse
import sys
import re
import time
from fabutils import *

alloc_addr_list = list()

import gevent
from gevent import monkey, Greenlet
monkey.patch_all()

class SafeList(list):
    def get(self, index, default=None):
        try:
            return super(SafeList, self).__getitem__(index)
        except IndexError:
            return default

def get_random_mac():
    return ':'.join(map(lambda x: "%02x" % x, [0x00, 0x16, 0x3E,
        random.randint(0x00, 0x7F), random.randint(0x00, 0xFF),
        random.randint(0x00, 0xFF)]))

def exec_in_parallel(functions_and_args):
    # Pass in Functions, args and kwargs in the below format
    # exec_in_parallel([(self.test, (val1, val2), {key3: val3})])
    greenlets = list()
    for fn_and_arg in functions_and_args:
        instance = SafeList(fn_and_arg)
        fn = instance[0]
        args = instance.get(1, set())
        kwargs = instance.get(2, dict())
        greenlets.append(Greenlet.spawn(fn, *args, **kwargs))
        gevent.sleep(0)
    return greenlets

def get_results(greenlets, raise_exception=True):
    outputs = list()
    results = list()
    for greenlet in greenlets:
        results.extend(gevent.joinall([greenlet]))
    for result in results:
        try:
            outputs.append(result.get())
        except:
            if raise_exception:
                raise
            outputs.append(None)
    return outputs

class Scale(object):
    def __init__ (self, args):
        self.client_h = Client(args)
        self.args = args
        self.fabric = args.fabric
        self.asn = args.asn
        self.peers = args.spines
        self.threads = int(getattr(args, 'threads', 1))
        self.vns = dict()
        self.vms = dict()
        self.reserved_pool = set()
        self.free_pool = list()
        self.reserved_pifs = set()
        self.free_pifs = list()
        self.server_info = dict()
        self.populate_mock_servers()

    def populate_mock_servers(self):
        self.mock_servers = dict()
        mock = self.args.mock
        for profile in mock['profiles']:
            self.mock_servers[profile['prefix']] = BMS(profile['mgmt_ip'],
                                          mock['username'],
                                          mock['password'],
                                          profile=profile)
        for index in range(IPAddress(mock['address']['start']).value,
                           IPAddress(mock['address']['end']).value):
            self.free_pool.append(index)

        for name, mock_server in self.mock_servers.items():
            start_index = mock_server.profile['start_index']
            for index in range(start_index, mock_server.profile['count']+start_index):
                qfx_name = self.get_qfx_name(name, index)
                self.server_info[qfx_name] = {'ip': str(IPAddress(self.reserve_address())),
                                              'bms': mock_server}

    def reserve_address(self):
        address = self.free_pool.pop()
        self.reserved_pool.add(address)
        return address

    def get_fqname(self, prefix, index):
        return ['default-domain', self.args.project_name, prefix+'-'+str(index)]

    def get_qfx_name(self, name, index):
        return '%s-%s.mock.net'%(name, index)

    def mock_start(self):
        gw_ip = self.args.mock['address']['gw']
        for name, mock_server in self.mock_servers.items():
            mock_server.run("pip install netconf jinja2 gevent exabgp")
            mock_server.run("yum install -y nc")
            start_index = mock_server.profile['start_index']
            for index in range(start_index, mock_server.profile['count']+start_index):
                mac_addr = get_random_mac()
                qfx_name = self.get_qfx_name(name, index)
                lo_ip = self.server_info[qfx_name]['ip']
                mock_server.create_mock_server(qfx_name, index, lo_ip, mac_addr, gw_ip, self.asn, self.peers)

    def mock_stop(self):
        for name, mock_server in self.mock_servers.items():
            start_index = mock_server.profile['start_index']
            for index in range(start_index, mock_server.profile['count']+start_index):
                qfx_name = self.get_qfx_name(name, index)
                mock_server.delete_mock_server(qfx_name)

    def onboard(self):
        self.mock_start()
        mock = self.args.mock
        fabric = self.client_h.read_fabric(self.fabric)
        for kvp in fabric.get_annotations().get_key_value_pair():
            if kvp.key.lower() == 'user_input':
                payload = json.loads(kvp.value)
                break
        payload.pop('supplemental_day_0_cfg', None)
        payload.pop('import_configured', None)
        payload.pop('device_to_ztp', None)
        payload['device_auth'].append({"username": mock['username'],
                                       "password": mock['password']})
        cidrs = [{"cidr": "%s/32"%IPAddress(addr)} for addr in self.reserved_pool]
        payload['management_subnets'] = cidrs
        fq_name = ['default-global-system-config',
                   'existing_fabric_onboard_template']
        self.client_h.execute_job(fq_name, payload)

    def get_mocked_device_names(self):
        devices = list()
        for name, mock_server in self.mock_servers.items():
            start_index = mock_server.profile['start_index']
            for index in range(start_index, mock_server.profile['count']+start_index):
                devices.append(self.get_qfx_name(name, index))
        return devices

    def assign_roles(self):
        devices = self.get_mocked_device_names()
        roles = list()
        for device in devices:
            fq_name = ['default-global-system-config', device]
            roles.append({'device_fq_name': fq_name,
                          'physical_role': 'leaf',
                          'routing_bridging_roles': ['ERB-UCAST-Gateway']})
        fq_name = ['default-global-system-config', 'role_assignment_template']
        payload = {'fabric_fq_name': ['default-global-system-config',
                                      self.fabric],
                   'role_assignments': roles}
        for device_roles in payload['role_assignments']:
            device = device_roles['device_fq_name']
            self.client_h.associate_physical_role(device,
                device_roles['physical_role'])
            for role in device_roles['routing_bridging_roles']:
                self.client_h.associate_rb_role(device, role.lower())
        execution_id = self.client_h.execute_job(fq_name, payload)
        return execution_id, None

    def init_pifs(self):
        mock = self.args.mock
        for name, mock_server in self.mock_servers.items():
            start_index = mock_server.profile['start_index']
            for index in range(start_index, mock_server.profile['count']+start_index):
                device_name = self.get_qfx_name(name, index)
                for pif_index in range(mock_server.profile['pifs']):
                    pif_name = 'default-global-system-config:'+device_name+':ge-0/0/%s'%pif_index
                    self.free_pifs.append(pif_name)

    def reserve_pif(self):
        pif = self.free_pifs.pop()
        self.reserved_pifs.add(pif)
        return pif.split(':')

    def get_vns(self, available_vns, max_vmi_per_vn, count):
        vns = list()
        while available_vns and len(vns) < count:
            vn = available_vns.pop()
            self.vns[vn]['count'] += 1
            vns.append(vn)
        for vn in vns:
            if self.vns[vn]['count'] < max_vmi_per_vn:
                available_vns.append(vn)
        return vns

    def delete(self):
        self.init_pifs()
        for name, profile in self.args.profiles.items():
            vlan = profile['vlan_start']
            free_vns = list()
            for i in range(profile['vn']):
                vn_fqname = self.get_fqname(name, i)
                free_vns.append(vn_fqname[-1])
                vn_obj = self.client_h.read_vn(fq_name=vn_fqname)
                rt = self.client_h.get_rt_of_vn(vn_fqname)
                self.vns[vn_fqname[-1]] = {'count': 0, 'obj': vn_obj, 'rt': rt}
            vmi_per_vn = ((profile['vmi_per_vpg'] * profile['vpg'])/profile['vn'])
            for i in range(profile['vpg']):
                pif = self.reserve_pif()
                vns = self.get_vns(free_vns, vmi_per_vn, profile['vmi_per_vpg'])
                for vn in vns:
                    vn_obj = self.vns[vn]['obj']
                    target = self.vns[vn]['rt'][0]
                    vni = vn_obj.virtual_network_network_id
                    fq_name = ['default-domain', 'admin'] + [vn+'.%s'%self.vns[vn]['count']]
                    try:
                        ip, mac = self.client_h.get_vmi_ip_mac(fq_name=fq_name)
                        nh = self.server_info[pif[1]]['ip']
                        bms = self.server_info[pif[1]]['bms']
                        bms.withdraw_route(pif[1], target, mac, ip, nh, vni)
                        self.client_h.delete_port(fq_name)
                    except NoIdError:
                        continue
                vpg_fqname = ['default-global-system-config', self.fabric,
                              '%s_%s'%(pif[1], pif[2])]
                try:
                    vpg = self.client_h.delete_vpg(vpg_fqname)
                except NoIdError:
                    continue
            for i in range(profile['vn']):
                vn_fqname = self.get_fqname(name, i)
                self.client_h.delete_vn(vn_fqname)

    def create(self):
        self.init_pifs()
        for name, profile in self.args.profiles.items():
            vlan = profile['vlan_start']
            free_vns = list()
            for i in range(profile['vn']):
                vn_fqname = self.get_fqname(name, i)
                uuid = self.client_h.create_vn(vn_fqname)
                self.vns[vn_fqname[-1]] = {'uuid': uuid, 'vlan': vlan,
                                           'count': 0, 'fq_name': vn_fqname}
                vlan = vlan + 1
                free_vns.append(vn_fqname[-1])
            for vn, prop in self.vns.items():
                prop['obj'] = self.client_h.read_vn(fq_name=prop['fq_name'])
                prop['rt'] = self.client_h.get_rt_of_vn(prop['fq_name'])
            vmi_per_vn = ((profile['vmi_per_vpg'] * profile['vpg'])/profile['vn'])
            for i in range(profile['vpg']):
                pif = self.reserve_pif()
                vpg_fqname = ['default-global-system-config', self.fabric,
                              '%s_%s'%(pif[1], pif[2])]
                try:
                    vpg = self.client_h.create_vpg(vpg_fqname, [pif])
                except:
                    continue
                vns = self.get_vns(free_vns, vmi_per_vn, profile['vmi_per_vpg'])
                for vn in vns:
                    vn_obj = self.vns[vn]['obj']
                    target = self.vns[vn]['rt'][0]
                    vni = vn_obj.virtual_network_network_id
                    fq_name = vn_obj.fq_name[:2] + [vn+'.%s'%self.vns[vn]['count']]
                    bms_info = {'vpg': vpg_fqname[-1],
                                'interfaces': [{'switch_info': pif[1],
                                                'port_id': pif[2],
                                                'vlan': self.vns[vn]['vlan'],
                                                'fabric': self.fabric}]
                                }
                    try:
                        self.client_h.create_port(fq_name, vn_obj, bms_info=bms_info)
                        ip, mac = self.client_h.get_vmi_ip_mac(fq_name=fq_name)
                        nh = self.server_info[pif[1]]['ip']
                        bms = self.server_info[pif[1]]['bms']
                        bms.advertise_route(pif[1], target, mac, ip, nh, vni)
                    except:
                        continue

    def create_one_batch(self):
        self.init_pifs()
        pif = self.reserve_pif()
        vn_fqname = self.get_fqname('test-onebatch', 1)
        uuid = self.client_h.create_vn(vn_fqname)
        vn_obj = self.client_h.read_vn(fq_name=vn_fqname)
        vpg_fqname = ['default-global-system-config', self.fabric,
                      '%s_%s'%(pif[1], pif[2])]
        vpg = self.client_h.create_vpg(vpg_fqname, [pif])
        bms_info = {'vpg': vpg_fqname[-1],
                    'interfaces': [{'switch_info': pif[1],
                                    'fabric': self.fabric,
                                    'port_id': pif[2], 'vlan': 4000}],
                    }
        self.client_h.create_port(vn_fqname, vn_obj, bms_info=bms_info)

class Client(object):
    def __init__ (self, args):
        domain_name = 'default-domain' if args.domain_name == 'Default' \
                                       else args.domain_name
        match = re.match(r'(.*?)://(.*?):([\d]+).*$', args.auth_url, re.M|re.I)
        if match:
            auth_protocol = match.group(1)
            auth_host = match.group(2)
            auth_port = match.group(3)

        self.vnc = VncApi(username=args.username,
                          password=args.password,
                          tenant_name=args.project_name,
                          api_server_host=args.api_server_ip,
                          auth_host=auth_host)

    def create_vn(self, fq_name, asn=None, rt=None, peer_rt_list=None):
        mask = 27
        cidr = get_random_cidr(mask=mask).split('/')[0]
        vn_name = fq_name[-1]
        vn_obj = VirtualNetwork(vn_name, parent_type='project',
                                fq_name=fq_name)
        vn_obj.add_network_ipam(NetworkIpam(),
                                VnSubnetsType([IpamSubnetType(
                                subnet=SubnetType(cidr, mask))]))
        if rt and asn:
            vn_obj.set_route_target_list(RouteTargetList(
                route_target=['target:%s:%s'%(asn, rt)]))
            vn_obj.set_import_route_target_list(RouteTargetList(
                route_target=peer_rt_list))
        try:
            vn_id = self.vnc.virtual_network_create(vn_obj)
        except RefsExistError:
            vn_id = self.vnc.virtual_network_read(fq_name=fq_name).uuid
        print 'Created VN', fq_name[-1], 'vni -', vn_obj.virtual_network_network_id
        return vn_id

    def create_vpg(self, fq_name, pifs=None):
        obj = VirtualPortGroup(fq_name[-1], fq_name=fq_name,
                               parent_type='fabric')
        try:
            uuid = self.vnc.virtual_port_group_create(obj)
        except RefsExistError:
            return self.vnc.virtual_port_group_read(fq_name=fq_name).uuid
        if pifs:
            for pif in pifs:
                pif_obj = self.vnc.physical_interface_read(fq_name=pif)
                obj.add_physical_interface(pif_obj)
            self.vnc.virtual_port_group_update(obj)
        print 'Created VPG', fq_name[-1]
        return uuid

    def delete_vpg(self, fq_name):
        self.vnc.virtual_port_group_delete(fq_name=fq_name)
        print 'Deleted VPG', fq_name[-1]

    def read_vn(self, fq_name):
        return self.vnc.virtual_network_read(fq_name=fq_name)

    def delete_vn(self, fq_name):
        try:
            self.vnc.virtual_network_delete(fq_name=fq_name)
            print 'Deleted VN', fq_name[-1]
        except NoIdError:
            pass

    def check_and_create_port(self, fq_name, vn_obj, device_owner=None):
        try:
            return self.read_port(fq_name=fq_name)
        except NoIdError:
            return self.create_port(fq_name, vn_obj, device_owner=None)

    def create_port(self, fq_name, vn_obj, device_owner=None,
                    bms_info=None):
        port_obj = VirtualMachineInterface(fq_name[-1],
            fq_name=fq_name, parent_type='project')
        port_obj.add_virtual_network(vn_obj)
        if bms_info:
            vlan = bms_info.pop('vlan', None)
            if vlan:
                vmi_props = VirtualMachineInterfacePropertiesType()
                vmi_props.set_sub_interface_vlan_tag(int(vlan))
                port_obj.set_virtual_machine_interface_properties(vmi_props)
            kv_pairs = KeyValuePairs()
            vnic_kv = KeyValuePair(key='vnic_type', value='baremetal')
            kv_pairs.add_key_value_pair(vnic_kv)
            vpg = bms_info.pop('vpg', None)
            if vpg:
                vpg_kv = KeyValuePair(key='vpg', value=vpg)
                kv_pairs.add_key_value_pair(vpg_kv)
            device_owner = 'baremetal:None'
            ll_info = {'local_link_information': bms_info['interfaces']}
            bind_kv = KeyValuePair(key='profile', value=json.dumps(ll_info))
            kv_pairs.add_key_value_pair(bind_kv)
            port_obj.set_virtual_machine_interface_bindings(kv_pairs)
        if device_owner:
            port_obj.set_virtual_machine_interface_device_owner(device_owner)
        try:
            self.vnc.virtual_machine_interface_create(port_obj)
        except RefsExistError:
            return self.vnc.virtual_machine_interface_read(fq_name=fq_name)
        iip_obj = InstanceIp(name=fq_name[-1])
        iip_obj.add_virtual_network(vn_obj)
        iip_obj.add_virtual_machine_interface(port_obj)
        self.vnc.instance_ip_create(iip_obj)
        print 'Created VMI', fq_name[-1]
        return port_obj

    def delete_port(self, fq_name):
        try:
            self.vnc.instance_ip_delete(fq_name=fq_name[-1:])
        except NoIdError:
            pass
        try:
            self.vnc.virtual_machine_interface_delete(fq_name=fq_name)
            print 'Deleted VMI', fq_name[-1]
        except NoIdError:
            pass

    def read_port(self, **kwargs):
        return self.vnc.virtual_machine_interface_read(**kwargs)

    def create_router(self, fq_name, vns):
        obj = LogicalRouter(name=fq_name[-1], parent_type='project',
                            fq_name=fq_name,
                            logical_router_type='snat-routing')
        for vn in vns:
            vn_obj = self.read_vn(fq_name=vn)
            ipam_refs = vn_obj.get_network_ipam_refs()
            for ipam_ref in ipam_refs or []:
                subnet = ipam_ref['attr'].get_ipam_subnets()[0]
                gateway = subnet.default_gateway
                break
            port_fq_name = list(vn_obj.fq_name)
            port_fq_name[-1] = port_fq_name[-1]+'-rtr-vmi'
            port_obj = self.check_and_create_port(port_fq_name,
                vn_obj, device_owner="network:router_interface")
            obj.add_virtual_machine_interface(port_obj)
        print 'Created LR', fq_name[-1]
        return self.vnc.logical_router_create(obj)

    def delete_router(self, fq_name, vns):
        try:
            self.vnc.logical_router_delete(fq_name=fq_name)
        except NoIdError:
            pass
        for vn in vns:
            try:
                vn_obj = self.read_vn(fq_name=vn)
            except NoIdError:
                continue
            port_fq_name = vn_obj.fq_name
            port_fq_name[-1] = port_fq_name[-1]+'-rtr-vmi'
            try:
                self.delete_port(fq_name=port_fq_name)
            except RefsExistError:
                continue
        print 'Deleted LR', fq_name[-1]

    def get_rt_of_vn(self, fq_name):
        ri_fqname = fq_name + fq_name[-1:]
        for i in range(30):
            ri_obj = self.vnc.routing_instance_read(fq_name=ri_fqname)
            targets = list()
            for rt in ri_obj.get_route_target_refs() or []:
                targets.extend(rt['to'])
            if not targets:
                time.sleep(1)
                continue
            return targets

    def get_vmi_ip_mac(self, **kwargs):
        vmi_obj = self.read_port(**kwargs)
        mac = vmi_obj.get_virtual_machine_interface_mac_addresses().mac_address[0]
        for iip in vmi_obj.get_instance_ip_back_refs() or []:
            iip_obj = self.vnc.instance_ip_read(id=iip['uuid'])
            return iip_obj.instance_ip_address, mac
        return None, mac

    def read_fabric(self, name):
        fq_name = ['default-global-system-config', name]
        return self.vnc.fabric_read(fq_name=fq_name)

    def execute_job(self, template_fqname, payload_dict, devices=None):
        kwargs = {'job_template_fq_name': template_fqname,
                  'job_input': payload_dict}
        if devices:
            kwargs['device_list'] = devices
        resp = self.vnc.execute_job(**kwargs)
        print 'Logic to wait for job to finish is not yet implemented'
        print 'Continue from pdb once job is completed'
        import pdb; pdb.set_trace()
        return resp['job_execution_id']

    def read_overlay_role(self, role):
        return self.vnc.overlay_role_read(
            fq_name=['default-global-system-config', role])

    def read_physical_role(self, role):
        return self.vnc.physical_role_read(
            fq_name=['default-global-system-config', role])

    def read_physical_router(self, name=None, **kwargs):
        if name:
            kwargs['fq_name'] = ['default-global-system-config', name]
        return self.vnc.physical_router_read(**kwargs)

    def associate_rb_role(self, prouter, rb_role):
        prouter_obj = self.read_physical_router(fq_name=prouter)
        role_obj = self.read_overlay_role(rb_role)
        prouter_obj.add_overlay_role(role_obj)
        self.vnc.physical_router_update(prouter_obj)

    def associate_physical_role(self, prouter, role):
        prouter_obj = self.read_physical_router(fq_name=prouter)
        role_obj = self.read_physical_role(role)
        prouter_obj.add_physical_role(role_obj)
        self.vnc.physical_router_update(prouter_obj)

def is_valid_address(address):
    ''' Validate whether the address provided is routable unicast address '''
    addr = IPAddress(address)
    if addr.is_loopback() or addr.is_reserved() or addr.is_private()\
       or addr.is_link_local() or addr.is_multicast():
        return False
    return True

def get_random_cidr(mask=28):
    ''' Generate random non-overlapping cidr '''
    global alloc_addr_list
    address = socket.inet_ntop(socket.AF_INET,
                               struct.pack('>I',
                               random.randint(2**24, 2**32 - 2**29 - 1)))
    addr = str(IPNetwork(address+'/'+str(mask)).network)
    if not is_valid_address(address) or addr in alloc_addr_list:
        cidr = get_random_cidr()
    else:
        alloc_addr_list.append(addr)
        cidr = addr+'/'+str(mask)
    return cidr

def parse_cli(args):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-t', '--template', required=True, metavar="FILE",
                        help='location of the yaml template files')
    parser.add_argument('-o', '--oper', default='add',
                        help='Operation to perform (add/delete)')
    parser.add_argument('-c', '--custom-cmd',
                        help='Any custom command to execute on VMs')
    pargs = parser.parse_args(args)
    return pargs

def main(template, oper, custom_cmd):
    with open(template, 'r') as fd:
        try:
            yargs = yaml.load(fd)
        except yaml.YAMLError as exc:
            print exc
            raise
    pargs = argparse.Namespace(**yargs)
    obj = Scale(pargs)
    if oper.lower().startswith('del'):
        obj.delete()
    elif oper.lower() == 'add':
        obj.create()
    elif getattr(obj, oper.lower(), None):
        fn = getattr(obj, oper.lower())
        fn()
    else:
        raise Exception()

if __name__ == '__main__':
    pargs = parse_cli(sys.argv[1:])
    main(pargs.template, pargs.oper, pargs.custom_cmd)
