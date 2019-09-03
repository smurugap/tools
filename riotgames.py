import random
import socket
import struct
from netaddr import *

from novaclient import client as nova_client
from keystoneclient import client as ks_client
from keystoneauth1 import identity
from keystoneauth1 import session
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
        self.ntierapp = list()
        self.server = self.client = None
        for name, profile in args.networks.items():
            if profile['mode'] == 'server':
                self.server = name
            elif profile['mode'] == 'client':
                self.client = name
            else:
                self.ntierapp.append(name)
        self.start_port = getattr(args, 'start_port', 5000)
        self.threads = int(getattr(args, 'threads', 1))
        self.vns = dict()
        self.vms = dict()

    def get_fqname(self, prefix, index):
        return ['default-domain', self.args.project_name, prefix+'-'+str(index)]

    def get_sec_fqname(self, prefix, index=None):
        name = prefix+'-'+str(index) if index else prefix
        return ['default-policy-management', name]

    def get_port(self, index):
        return (self.start_port+index, self.start_port+index)

    def create_logical_routers(self, name, index):
        if self.client == name:
            vn_fqname = self.get_fqname(self.client, index)
            server_count = self.args.networks[self.server]['count']
            for i in range(server_count):
                svn_fqname = self.get_fqname(self.server, i)
                lr_fqname = self.get_fqname(vn_fqname[-1], i)
                self.client_h.create_router(lr_fqname, [vn_fqname, svn_fqname])

    def delete_logical_routers(self, name, index):
        if self.client == name:
            vn_fqname = self.get_fqname(self.client, index)
            server_count = self.args.networks[self.server]['count']
            for i in range(server_count):
                svn_fqname = self.get_fqname(self.server, i)
                lr_fqname = self.get_fqname(vn_fqname[-1], i)
                self.client_h.delete_router(lr_fqname, [vn_fqname, svn_fqname])

    def get_rules(self, name, index):
        rules = list()
        if self.client == name:
            server_count = self.args.networks[self.server]['count']
            for i in range(server_count):
                rule = dict()
                rule['dports'] = self.get_port(i)
                rule['protocol'] = 'tcp'
                rule['action'] = 'pass'
                rule['source'] = {'virtual_network': ':'.join(self.get_fqname(self.client, index))}
                rule['destination'] = {'virtual_network': ':'.join(self.get_fqname(self.server, i))}
                rules.append(rule)
        elif self.server == name:
            client_count = self.args.networks[self.client]['count']
            for i in range(client_count):
                rule = dict()
                rule['dports'] = self.get_port(index)
                rule['protocol'] = 'tcp'
                rule['action'] = 'pass'
                rule['source'] = {'virtual_network': ':'.join(self.get_fqname(self.client, i))}
                rule['destination'] = {'virtual_network': ':'.join(self.get_fqname(self.server, index))}
                rules.append(rule)
        return rules

    def get_dummy_rules(self, start, end):
        rules = list()
        subnet = get_random_cidr(mask=30)
        for i in range(start, end):
            rule = dict()
            rule['dports'] = (65000 - i, 65000 - i)
            rule['sports'] = (65000 - i, 65000 - i)
            rule['protocol'] = 'udp'
            rule['action'] = 'pass'
            rule['destination'] = {'subnet': subnet}
            rule['source'] = {'subnet': subnet}
            rules.append(rule)
        return rules

    def get_greenlet_args_list(self, fn, name, profile):
        count = int(profile.get('count', 1))
        n_vms = int(float(profile.get('vms', 1)) * count)
        total_vms = 0
        start = 0
        each = count/self.threads
        greenlet_args_list = list()
        for thread in range(self.threads):
            end = start + each
            if end + each > count:
                end = count
            kwargs = {'name': name, 'profile': profile}
            kwargs['start'] = start
            kwargs['end'] = end
            kwargs['n_vms'] = each if n_vms - each*(thread+1) >= 0 else 0
            total_vms = total_vms + kwargs['n_vms']
            if kwargs['n_vms'] == 0 and total_vms < n_vms:
                kwargs['n_vms'] = n_vms - total_vms
                total_vms = total_vms + kwargs['n_vms']
            start = end
            greenlet_args_list.append((fn, set(), kwargs))
        return greenlet_args_list

    def start_traffic(self):
        #Get all VM objects
        for name, profile in self.args.networks.items():
            fn_and_args = self.get_greenlet_args_list(self.get_vm_details, name, profile)
            greenlets = exec_in_parallel(fn_and_args)
            get_results(greenlets, raise_exception=True)
        #Start servers
        if self.server:
            profile = self.args.networks[self.server]
            for i in range(profile['count']):
                port = list(self.get_port(i))[0]
                vn_fqname = self.get_fqname(self.server, i)
                vm = self.vms[vn_fqname[-1]]
                vm.start_traffic('tcp', port, mode='server')
                print (vm.vmi_fqname, vm.vm_node_ip, vm.local_ip)
        #Start clients
        if self.client:
            cprofile = self.args.networks[self.client]
            sprofile = self.args.networks[self.server]
            n_vms = int(float(cprofile.get('vms', 1)) * cprofile['count'])
            vms = 0
            for cindex in range(cprofile['count']):
                if vms >= n_vms:
                    break
                cvn_fqname = self.get_fqname(self.client, cindex)
                cvm = self.vms[cvn_fqname[-1]]
                for sindex in range(sprofile['count']):
                    port = list(self.get_port(sindex))[0]
                    svn_fqname = self.get_fqname(self.server, sindex)
                    svm = self.vms[svn_fqname[-1]]
                    cvm.start_traffic('tcp', port, mode='client', server=svm.vm_ip)
                vms = vms+1

    def stop_traffic(self):
        #Get all VM objects
        for name, profile in self.args.networks.items():
            fn_and_args = self.get_greenlet_args_list(self.get_vm_details, name, profile)
            greenlets = exec_in_parallel(fn_and_args)
            get_results(greenlets, raise_exception=True)
        #Poll clients
        if self.client:
            cprofile = self.args.networks[self.client]
            sprofile = self.args.networks[self.server]
            n_vms = int(float(cprofile.get('vms', 1)) * cprofile['count'])
            vms = 0
            for cindex in range(cprofile['count']):
                if vms >= n_vms:
                    break
                cvn_fqname = self.get_fqname(self.client, cindex)
                cvm = self.vms[cvn_fqname[-1]]
                for sindex in range(sprofile['count']):
                    port = list(self.get_port(sindex))[0]
                    svn_fqname = self.get_fqname(self.server, sindex)
                    svm = self.vms[svn_fqname[-1]]
                    sent, recv = cvm.stop_traffic('tcp', port, server=svm.vm_ip)
                    if sent - recv > 1:
                        print 'Drops: %s - Client: %s - Server: %s'%(sent-recv,
                            cvn_fqname[-1], svn_fqname[-1])
                vms = vms+1

    def poll_traffic(self):
        #Get all VM objects
        for name, profile in self.args.networks.items():
            fn_and_args = self.get_greenlet_args_list(self.get_vm_details, name, profile)
            greenlets = exec_in_parallel(fn_and_args)
            get_results(greenlets, raise_exception=True)
        #Poll clients
        if self.client:
            cprofile = self.args.networks[self.client]
            sprofile = self.args.networks[self.server]
            n_vms = int(float(cprofile.get('vms', 1)) * cprofile['count'])
            vms = 0
            for cindex in range(cprofile['count']):
                if vms >= n_vms:
                    break
                cvn_fqname = self.get_fqname(self.client, cindex)
                cvm = self.vms[cvn_fqname[-1]]
                for sindex in range(sprofile['count']):
                    port = list(self.get_port(sindex))[0]
                    svn_fqname = self.get_fqname(self.server, sindex)
                    svm = self.vms[svn_fqname[-1]]
                    sent, recv = cvm.poll_traffic('tcp', port, server=svm.vm_ip)
                    if sent - recv > 1:
                        print 'Drops: %s - Client: %s - Server: %s'%(sent-recv,
                            cvn_fqname[-1], svn_fqname[-1])
                    sent2, recv2 = cvm.poll_traffic('tcp', port, server=svm.vm_ip)
                    if sent2 == sent:
                        print 'traffic stopped - Client: %s - Server: %s'%(sent-recv,
                            cvn_fqname[-1], svn_fqname[-1])
                vms = vms+1

    def get_vm_details(self, name, profile, start, end, n_vms, **kwargs):
        count_vms = 0
        for i in range(start, end):
            vn_fqname = self.get_fqname(name, i)
            if count_vms < n_vms:
                self.vms[vn_fqname[-1]] = VM(vn_fqname, self.client_h)
                count_vms = count_vms + 1
                self.vms[vn_fqname[-1]].vm_ip, self.vms[vn_fqname[-1]].local_ip

    def create(self):
        for name, profile in self.args.networks.items():
            fn_and_args = self.get_greenlet_args_list(self._create, name, profile)
            greenlets = exec_in_parallel(fn_and_args)
            get_results(greenlets, raise_exception=True)

        for name, profile in self.args.networks.items():
            for i in range(profile['count']):
                self.create_logical_routers(name, i)

    def _create(self, name, profile, start, end, n_vms, **kwargs):
        count_vms = 0
        for i in range(start, end):
            vn_fqname = self.get_fqname(name, i)
            self.vns[vn_fqname[-1]] = self.client_h.create_vn(vn_fqname)
            vn_obj = self.client_h.read_vn(fq_name=vn_fqname)
            if count_vms < n_vms:
                port_obj = self.client_h.create_port(vn_fqname, vn_obj)
                self.client_h.create_vm(vn_fqname[-1], port_obj.uuid)
                count_vms = count_vms + 1
            self.client_h.create_tag(vn_fqname[-1:], 'application', vn_fqname[-1])
            self.client_h.set_tag('application', vn_fqname[-1], 'virtual_network',
                                  vn_fqname)
            rules = self.get_rules(name, i)[:profile['rule_count']]
            rules.extend(self.get_dummy_rules(len(rules), profile['rule_count']))
            fw_rules = list()
            for rindex, rule in enumerate(rules):
                fwr = self.client_h.create_firewall_rule(
                    self.get_sec_fqname(vn_fqname[-1], rindex),
                        **rule)
                fw_rules.append({'seq_no': rindex, 'uuid': fwr})
            fwp = self.client_h.create_firewall_policy(
                self.get_sec_fqname(vn_fqname[-1]),
                rules=fw_rules)
            aps = self.client_h.create_application_policy_set(
                self.get_sec_fqname(vn_fqname[-1]),
                policies=[{'uuid': fwp, 'seq_no': 1}])
            self.client_h.set_tag('application', vn_fqname[-1],
                'application-policy-set',
                 self.get_sec_fqname(vn_fqname[-1]))

    def delete(self):
        for name, profile in self.args.networks.items():
            for i in range(profile['count']):
                self.delete_logical_routers(name, i)
        for name, profile in self.args.networks.items():
            fn_and_args = self.get_greenlet_args_list(self._delete, name, profile)
            greenlets = exec_in_parallel(fn_and_args)
            get_results(greenlets, raise_exception=True)

    def _delete(self, name, profile, start, end, n_vms, **kwargs):
        count_vms = 0
        for i in range(start, end):
            vn_fqname = self.get_fqname(name, i)
            if count_vms < n_vms:
                self.client_h.delete_vm(vn_fqname)
                count_vms = count_vms + 1
            self.client_h.delete_application_policy_set(self.get_sec_fqname(vn_fqname[-1]))
            self.client_h.delete_firewall_policy(self.get_sec_fqname(vn_fqname[-1]))
            for index in range(profile['rule_count']):
                self.client_h.delete_firewall_rule(self.get_sec_fqname(vn_fqname[-1], index))
            self.client_h.delete_vn(vn_fqname)
            self.client_h.delete_tag(vn_fqname[-1:], 'application')

class Client(object):
    def __init__ (self, args):
        auth = identity.v3.Password(auth_url=args.auth_url,
                                    username=args.username,
                                    password=args.password,
                                    user_domain_name=args.domain_name,
                                    project_domain_name=args.domain_name,
                                    project_name=args.project_name)
        sess = session.Session(auth=auth, verify=False)
        self.keystone = ks_client.Client(version='3', session=sess,
            auth_url=args.auth_url, insecure=True)
        self.nova = nova_client.Client('2', session=sess)
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
                          domain_name=domain_name,
                          api_server_host=args.api_server_ip,
                          auth_host=auth_host)
        self.flavor = args.flavor
        self.image = args.image

    def create_vn(self, fq_name):
        mask = 29
        cidr = get_random_cidr(mask=mask).split('/')[0]
        vn_name = fq_name[-1]
        vn_obj = VirtualNetwork(vn_name, parent_type='project',
                                fq_name=fq_name)
        vn_obj.add_network_ipam(NetworkIpam(),
                                VnSubnetsType([IpamSubnetType(
                                subnet=SubnetType(cidr, mask))]))
        vn_id = self.vnc.virtual_network_create(vn_obj)
        return vn_id

    def read_vn(self, fq_name):
        return self.vnc.virtual_network_read(fq_name=fq_name)

    def delete_vn(self, fq_name):
        try:
            self.vnc.virtual_network_delete(fq_name=fq_name)
        except NoIdError:
            pass

    def create_application_policy_set(self, fq_name, policies=None):
        obj = ApplicationPolicySet(fq_name[-1], fq_name=fq_name,
                                   parent_type='policy-management')
        for policy in policies or []:
            policy_obj = self.read_firewall_policy(id=policy['uuid'])
            seq = FirewallSequence(str(policy['seq_no']))
            obj.add_firewall_policy(policy_obj, seq)
        return self.vnc.application_policy_set_create(obj)

    def delete_application_policy_set(self, fq_name):
        try:
            self.vnc.application_policy_set_delete(fq_name=fq_name)
        except NoIdError:
            pass

    def create_firewall_policy(self, fq_name, rules=None):
        obj = FirewallPolicy(fq_name[-1], fq_name=fq_name,
                             parent_type='policy-management')
        for rule in rules or []:
            seq = FirewallSequence(str(rule['seq_no']))
            rule_obj = self.read_firewall_rule(id=rule['uuid'])
            obj.add_firewall_rule(rule_obj, seq)
        return self.vnc.firewall_policy_create(obj)

    def delete_firewall_policy(self, fq_name):
        try:
            self.vnc.firewall_policy_delete(fq_name=fq_name)
        except NoIdError:
            pass

    def read_firewall_policy(self, **kwargs):
        return self.vnc.firewall_policy_read(**kwargs)

    def _get_fw_endpoint_obj(self, endpoint):
        if not endpoint:
            return None
        subnet = None
        if endpoint.get('subnet'):
            subnet = SubnetType(*endpoint['subnet'].split('/'))
        vn = endpoint.get('virtual_network')
        ag = endpoint.get('address_group')
        tags = endpoint.get('tags', [])
        any = endpoint.get('any', False)
        return FirewallRuleEndpointType(subnet=subnet, virtual_network=vn,
                                        address_group=ag, tags=tags, any=any)

    def create_firewall_rule(
            self,
            fq_name,
            action=None,
            protocol=None,
            sports=None,
            dports=None,
            source=None,
            destination=None,
            match=None,
            **kwargs):
        ''' Create a firewall policy rule
            :param fq_name : name of the policy rule
            :param action : pass or deny
            :param direction : <> or < or >
            :param service_groups : list of service_group uuids
            :param protocol : protocol to filter (int or one of icmp/tcp/udp/any)
            :param sports : tuple of start,end port
            :param dports : tuple of start,end port
            :param log : to log flow to analytics
            :param match : list of match tag-types ['deployment', 'site']
            :param source : dict for endpoint
            :param destination : dict for endpoint
            eg: endpoint dict
                {'subnet': '1.1.1.0/24', 'virtual_network': vn_fq_name, 'any': False,
                 'address_group': ag_fq_name,
                 'tags': ['deployment=prod', 'global:site=us'],
                }
        '''
        service = None
        if protocol or sports or dports:
            sports = sports if sports else (0, 65535)
            dports = dports if dports else (0, 65535)
            service = FirewallServiceType(protocol=protocol or 'any',
                                          src_ports=PortType(*sports),
                                          dst_ports=PortType(*dports))
        match = FirewallRuleMatchTagsType(tag_list=[])
        obj = FirewallRule(fq_name[-1],
                           fq_name=fq_name,
                           parent_type='policy-management',
                           action_list=ActionListType(simple_action=action),
                           service=service,
                           endpoint_1=self._get_fw_endpoint_obj(source),
                           endpoint_2=self._get_fw_endpoint_obj(destination),
                           match_tags=match)
        return self.vnc.firewall_rule_create(obj)

    def delete_firewall_rule(self, fq_name):
        try:
            self.vnc.firewall_rule_delete(fq_name=fq_name)
        except NoIdError:
            pass

    def read_firewall_rule(self, **kwargs):
        return self.vnc.firewall_rule_read(**kwargs)

    def check_and_create_tag(self, fq_name, tag_type,
                             tag_value, **kwargs):
        try:
            return self.create_tag(fq_name, tag_type, tag_value,
                                   parent_type=None, **kwargs)
        except RefsExistError:
            fqname = ['%s=%s' % (tag_type, tag_value)]
            if parent_type == 'project':
                fqname = fq_name[:-1] + fqname
            return self.read_tag(fq_name=fqname).uuid

    def create_tag(
            self,
            fq_name,
            tag_type,
            tag_value,
            parent_type=None,
            **kwargs):
        ''' Create a Tag
            :param fq_name : fqname of the Tag
            :param parent_type : parent type ('project' or None for global tag)
            :param tag_type : tag_type (Application/Tier/Site etal)
            :param tag_value : string representing the tag
        '''
        obj = Tag(fq_name[-1], tag_type_name=tag_type, tag_value=tag_value,
                  parent_type=parent_type, fq_name=fq_name, **kwargs)
        return self.vnc.tag_create(obj)

    def delete_tag(self, fq_name, tag_type=None):
        if tag_type:
            fq_name[-1] = tag_type+"="+fq_name[-1]
        try:
            self.vnc.tag_delete(fq_name=fq_name)
        except NoIdError:
            pass

    def read_tag(self, **kwargs):
        return self.vnc.tag_read(**kwargs)

    def _get_obj(self, object_type, fq_name):
        api = ('self.vnc.' + object_type + '_read').replace('-', '_')
        return eval(api)(fq_name=fq_name)

    def set_tag(self, tag_type, tag_value, object_type, fq_name):
        obj = self._get_obj(object_type, fq_name)
        return self.vnc.set_tag(obj, tag_type, tag_value, True)

    def unset_tag(self, tag_type, object_type, fq_name):
        obj = self._get_obj(object_type, fq_name)
        return self.vnc.unset_tag(obj, tag_type)

    def check_and_create_port(self, fq_name, vn_obj, device_owner=None):
        try:
            return self.read_port(fq_name=fq_name)
        except NoIdError:
            return self.create_port(fq_name, vn_obj, device_owner=None)

    def create_port(self, fq_name, vn_obj, device_owner=None):
        port_obj = VirtualMachineInterface(fq_name[-1],
            fq_name=fq_name, parent_type='project')
        port_obj.add_virtual_network(vn_obj)
        if device_owner:
            port_obj.set_virtual_machine_interface_device_owner(device_owner)
        self.vnc.virtual_machine_interface_create(port_obj)
        iip_obj = InstanceIp(name=fq_name[-1])
        iip_obj.add_virtual_network(vn_obj)
        iip_obj.add_virtual_machine_interface(port_obj)
        self.vnc.instance_ip_create(iip_obj)
        return port_obj

    def delete_port(self, fq_name):
        try:
            self.vnc.instance_ip_delete(fq_name=fq_name[-1:])
        except NoIdError:
            pass
        try:
            self.vnc.virtual_machine_interface_delete(fq_name=fq_name)
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
        uuid = self.vnc.logical_router_create(obj)
        return uuid

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

    def create_vm(self, vm_name, port_id):
        nics = [{'port-id': port_id}]
        response = self.nova.servers.create(name=vm_name,
                                            flavor=self.flavor,
                                            image=self.image,
                                            nics=nics)

    def delete_vm(self, vmi_fqname):
        try:
            vm_id = self.get_vm_id(vmi_fqname)
            if vm_id:
                self.nova.servers.delete(vm_id)
                #obj = self.get_vm_by_id(vm_id)
                #obj.delete()
            for i in range(10):
                try:
                    self.delete_port(vmi_fqname)
                    break
                except RefsExistError:
                    time.sleep(2)
        except NoIdError:
            pass
#    def delete_vm(self, vm_obj):
#        vm_obj.delete()

    def get_vm_by_id(self, vm_id):
        return self.nova.servers.get(vm_id)

    def get_vmi_ip(self, **kwargs):
        vmi_obj = self.read_port(**kwargs)
        for iip in vmi_obj.get_instance_ip_back_refs() or []:
            iip_obj = self.vnc.instance_ip_read(id=iip['uuid'])
            return iip_obj.instance_ip_address

    def get_vm_id(self, vmi_fqname):
        vmi_obj = self.read_port(fq_name=vmi_fqname)
        for ref in vmi_obj.get_virtual_machine_refs() or []:
            return ref['uuid']

    def get_vm_node(self, vm_id):
        vm_obj = self.get_vm_by_id(vm_id)
        return vm_obj.__dict__['OS-EXT-SRV-ATTR:hypervisor_hostname']

def get_random_cidr(mask=28):
    ''' Generate random non-overlapping cidr '''
    global alloc_addr_list
    address = socket.inet_ntop(socket.AF_INET,
                               struct.pack('>I',
                               random.randint(2**24, 2**32 - 2**29 - 1)))
    address = str(IPNetwork(address+'/'+str(mask)).network)
    if address.startswith('169.254') or address in alloc_addr_list:
        cidr = get_random_cidr()
    else:
        alloc_addr_list.append(address)
        cidr = address+'/'+str(mask)
    return cidr

def parse_cli(args):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-t', '--template', required=True, metavar="FILE",
                        help='location of the yaml template files')
    parser.add_argument('-o', '--oper', default='add',
                        help='Operation to perform (add/delete)')
    pargs = parser.parse_args(args)
    return pargs

def main(template, oper):
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
    elif oper.lower() == 'start':
        obj.start_traffic()
    elif oper.lower() == 'poll':
        obj.poll_traffic()
    elif oper.lower() == 'stop':
        obj.stop_traffic()
    else:
        raise Exception()

if __name__ == '__main__':
    pargs = parse_cli(sys.argv[1:])
    main(pargs.template, pargs.oper)
