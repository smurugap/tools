import random
import socket
import struct
import uuid
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
        self.server = self.client = None
        self.app_vns = list()
        self.service_vns = list()
        for name, profile in args.networks.items():
            if profile['mode'] == 'server':
                self.server = name
            elif profile['mode'] == 'client':
                self.client = name
            elif profile['mode'] == 'service':
                self.service_vns.append(name)
            elif profile['mode'] == 'application':
                self.app_vns.append(name)
        self.use_lr = getattr(args, 'use_logical_routers', False)
        self.start_port = getattr(args, 'start_port', 5000)
        self.threads = int(getattr(args, 'threads', 1))
        self.asn = getattr(args, 'asn', 64512)
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

    def get_peer_rt(self, name, index):
        import_rt_list = []
        if self.client == name:
            server_rt_start = self.args.networks[self.server]['rt_start']
            server_count = self.args.networks[self.server]['count']
            for i in range(server_count):
                import_rt_list.append('target:%s:%s'%(self.asn, 
                                      int(server_rt_start) + i))
        elif self.server == name:
            client_rt_start = self.args.networks[self.client]['rt_start']
            client_count = self.args.networks[self.client]['count']
            for i in range(client_count):
                import_rt_list.append('target:%s:%s'%(self.asn, 
                                      int(client_rt_start) + i))
        return import_rt_list

#    def exchange_route_targets(self, name, index):
#        if self.client == name:
#            vn_fqname = self.get_fqname(self.client, index)
#            server_count = self.args.networks[self.server]['count']
#            for i in range(server_count):
#                svn_fqname = self.get_fqname(self.server, i)
#                self.client_h.exchange_rt(vn_fqname, svn_fqname)

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

    def custom(self, custom_cmd):
        #Get all VM objects
        for name, profile in self.args.networks.items():
            for i in range(profile.get('count', 1)):
                vn_fqname = self.get_fqname(name, i)
                self.vms[vn_fqname[-1]] = VM(vn_fqname, self.client_h)
                vm = self.vms[vn_fqname[-1]]
                print 'VM - %s - %s'%(vm.local_ip, vm.vm_node_ip)
        for name, profile in self.args.networks.items():
            for i in range(profile.get('count', 1)):
                fab_connections.clear()
                vn_fqname = self.get_fqname(name, i)
                vm = self.vms[vn_fqname[-1]]
                print vm.run_cmd_on_vm(custom_cmd)
                print 'VM - %s - %s - %s - %s'%(vm.local_ip, vm.vm_node_ip, vm.vm_ip, vn_fqname[-1])
        '''
        #Start servers
        if self.server:
            profile = self.args.networks[self.server]
            for i in range(profile['count']):
                fab_connections.clear()
                port = list(self.get_port(i))[0]
                vn_fqname = self.get_fqname(self.server, i)
                vm = self.vms[vn_fqname[-1]]
                print 'Server VM - %s - %s'%(vm.local_ip, vm.vm_node_ip)
                try:
                    print vm.run_cmd_on_vm(custom_cmd)
                except:
                    pass
                print '\n'
        #Start clients
        if self.client:
            cprofile = self.args.networks[self.client]
            n_vms = int(float(cprofile.get('vms', 1)) * cprofile['count'])
            vms = 0
            for cindex in range(cprofile['count']):
                fab_connections.clear()
                if vms >= n_vms:
                    break
                vms = vms+1
                cvn_fqname = self.get_fqname(self.client, cindex)
                cvm = self.vms[cvn_fqname[-1]]
                print 'Client VM - %s - %s'%(cvm.local_ip, cvm.vm_node_ip)
                try:
                    print cvm.run_cmd_on_vm(custom_cmd)
                except:
                    pass
                print '\n'
        '''

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
                fab_connections.clear()
                port = list(self.get_port(i))[0]
                vn_fqname = self.get_fqname(self.server, i)
                vm = self.vms[vn_fqname[-1]]
                print 'Server VM - %s - %s'%(vm.local_ip, vm.vm_node_ip)
                vm.start_traffic('tcp', port, mode='server')
        #Start clients
        if self.client:
            cprofile = self.args.networks[self.client]
            sprofile = self.args.networks[self.server]
            n_vms = int(float(cprofile.get('vms', 1)) * cprofile['count'])
            vms = 0
            for cindex in range(cprofile['count']):
                fab_connections.clear()
                if vms >= n_vms:
                    break
                vms = vms+1
                cvn_fqname = self.get_fqname(self.client, cindex)
                cvm = self.vms[cvn_fqname[-1]]
                print 'Client VM - %s - %s'%(cvm.local_ip, cvm.vm_node_ip)
                for sindex in range(sprofile['count']):
                    port = list(self.get_port(sindex))[0]
                    svn_fqname = self.get_fqname(self.server, sindex)
                    svm = self.vms[svn_fqname[-1]]
                    cvm.start_traffic('tcp', port, mode='client', server=svm.vm_ip)

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
                fab_connections.clear()
                if vms >= n_vms:
                    break
                vms = vms+1
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
                fab_connections.clear()
                if vms >= n_vms:
                    break
                vms = vms+1
                cvn_fqname = self.get_fqname(self.client, cindex)
                cvm = self.vms[cvn_fqname[-1]]
                for sindex in range(sprofile['count']):
                    port = list(self.get_port(sindex))[0]
                    svn_fqname = self.get_fqname(self.server, sindex)
                    svm = self.vms[svn_fqname[-1]]
                    sent, recv = cvm.poll_traffic('tcp', port, server=svm.vm_ip)
                    print sent, recv, cvm.vm_ip, svm.vm_ip
                    if sent - recv > 1:
                        print 'ERROR: Drops: %s - Client: %s - Server: %s'%(sent-recv,
                            cvn_fqname[-1], svn_fqname[-1])
                    sent2, recv2 = cvm.poll_traffic('tcp', port, server=svm.vm_ip)
                    if sent2 == sent:
                        time.sleep(1)
                        sent2, recv2 = cvm.poll_traffic('tcp', port, server=svm.vm_ip)
                        if sent2 == sent:
                          print 'ERROR: Traffic stopped - Client: %s - Server: %s'%(
                            cvn_fqname[-1], svn_fqname[-1])

    def get_vm_details(self, name, profile, start, end, n_vms, **kwargs):
        count_vms = 0
        for i in range(start, end):
            vn_fqname = self.get_fqname(name, i)
            if count_vms < n_vms:
                self.vms[vn_fqname[-1]] = VM(vn_fqname, self.client_h)
                count_vms = count_vms + 1

    def _get_rules(self, rules, name, index):
        rules_list = list()
        if name in self.service_vns:
            min_index = 0
            max_index = self.args.networks[self.app_vns[0]]['count']
        else:
            min_index = index
            max_index = index + 1
        for index in range(min_index, max_index):
            for rule in rules:
                dct = dict()
                if 'dst_vn' in rule:
                    if rule['dst_vn'] in self.service_vns:
                        dct['dst_vn'] = self.get_fqname(rule['dst_vn'], 0)
                    else:
                        dct['dst_vn'] = self.get_fqname(rule['dst_vn'], index)
                else:
                    if name in self.service_vns:
                        dct['dst_vn'] = self.get_fqname(name, 0)
                    else:
                        dct['dst_vn'] = self.get_fqname(name, index)
                if 'src_vn' in rule:
                    if rule['src_vn'] in self.service_vns:
                        dct['src_vn'] = self.get_fqname(rule['src_vn'], 0)
                    else:
                        dct['src_vn'] = self.get_fqname(rule['src_vn'], index)
                else:
                    if name in self.service_vns:
                        dct['src_vn'] = self.get_fqname(name, 0)
                    else:
                        dct['src_vn'] = self.get_fqname(name, index)
                dct['port'] = rule['port']
                rules_list.append(dct)
        return rules_list

    def pre_start_traffic(self):
        for name, profile in self.args.networks.items():
            for i in range(profile.get('count', 1)):
                vn_fqname = self.get_fqname(name, i)
                self.vms[vn_fqname[-1]] = VM(vn_fqname, self.client_h)
        for name, profile in self.args.networks.items():
            for i in range(profile.get('count', 1)):
                fab_connections.clear()
                vn_fqname = self.get_fqname(name, i)
                rules = profile['rules'] + profile.get('traffic', [])
                servers = [rule for rule in rules if 'src_vn' in rule or 
                           ('dst_vn' not in rule and 'src_vn' not in rule)]
                vm = self.vms[vn_fqname[-1]]
                for traffic in servers:
                    vm.start_traffic('tcp', traffic['port'], mode='server')
                print 'VM - %s - %s'%(vm.local_ip, vm.vm_node_ip)
        for name, profile in self.args.networks.items():
            for i in range(profile.get('count', 1)):
                fab_connections.clear()
                vn_fqname = self.get_fqname(name, i)
                rules = profile['rules'] + profile.get('traffic', [])
                clients = [rule for rule in rules if 'dst_vn' in rule]
                vm = self.vms[vn_fqname[-1]]
                if name in self.service_vns:
                    min_index = 0
                    max_index = self.args.networks[self.app_vns[0]]['count']
                else:
                    min_index = i
                    max_index = i + 1
                for index in range(min_index, max_index):
                  for traffic in clients:
                    rindex = index
                    if traffic['dst_vn'] in self.service_vns:
                        rindex = 0
                    dvm = self.vms[self.get_fqname(traffic['dst_vn'], rindex)[-1]]
                    vm.start_traffic('tcp', traffic['port'], mode='client', server=dvm.vm_ip)
                vm = self.vms[vn_fqname[-1]]
                print 'VM - %s - %s - %s - %s'%(vm.local_ip, vm.vm_node_ip, vm.vm_ip, vn_fqname[-1])

    def poll_migrate_traffic(self):
        for name, profile in self.args.networks.items():
            for i in range(profile.get('count', 1)):
                vn_fqname = self.get_fqname(name, i)
                self.vms[vn_fqname[-1]] = VM(vn_fqname, self.client_h)
        for name, profile in self.args.networks.items():
            for i in range(profile.get('count', 1)):
                fab_connections.clear()
                vn_fqname = self.get_fqname(name, i)
                rules = profile['rules']
                clients = [rule for rule in rules if 'dst_vn' in rule]
                vm = self.vms[vn_fqname[-1]]
                if name in self.service_vns:
                    min_index = 0
                    max_index = self.args.networks[self.app_vns[0]]['count']
                else:
                    min_index = i
                    max_index = i + 1
                for index in range(min_index, max_index):
                  for traffic in clients:
                    if traffic['dst_vn'] in self.service_vns:
                        index = 0
                    dvm = self.vms[self.get_fqname(traffic['dst_vn'], index)[-1]]
                    sent, recv = vm.poll_traffic('tcp', traffic['port'], server=dvm.vm_ip)
                    print sent, recv, vm.vm_ip, dvm.vm_ip, vn_fqname[-1], dvm.vmi_fqname[-1]
                    if sent - recv > 1:
                        print 'ERROR: Drops: %s - Client: %s - Server: %s'%(sent-recv,
                            vn_fqname[-1], self.get_fqname(traffic['dst_vn'], index)[-1])
                    sent2, recv2 = vm.poll_traffic('tcp', traffic['port'], server=dvm.vm_ip)
                    if sent2 == sent:
                        time.sleep(1)
                        sent2, recv2 = vm.poll_traffic('tcp', traffic['port'], server=dvm.vm_ip)
                        if sent2 == sent:
                          print 'ERROR: Traffic stopped - Client: %s - Server: %s'%(
                            vn_fqname[-1], self.get_fqname(traffic['dst_vn'], index)[-1])

        for name, profile in self.args.networks.items():
            for i in range(profile.get('count', 1)):
                fab_connections.clear()
                vn_fqname = self.get_fqname(name, i)
                rules = profile.get('traffic', [])
                clients = [rule for rule in rules if 'dst_vn' in rule]
                vm = self.vms[vn_fqname[-1]]
                for traffic in clients:
                    index = i
                    if traffic['dst_vn'] in self.service_vns:
                        index = 0
                    dvm = self.vms[self.get_fqname(traffic['dst_vn'], index)[-1]]
                    sent, recv = vm.poll_traffic('tcp', traffic['port'], server=dvm.vm_ip)
                    print sent, recv, vm.vm_ip, dvm.vm_ip
                    if recv:
                        print 'ERROR: Negative: recv: %s - Client: %s - Server: %s'%(recv,
                            vn_fqname[-1], self.get_fqname(traffic['dst_vn'], index)[-1])

                vm = self.vms[vn_fqname[-1]]
                print 'VM - %s - %s - %s - %s'%(vm.local_ip, vm.vm_node_ip, vm.vm_ip, vn_fqname[-1])

    def recreate_np(self):
        for name, profile in self.args.networks.items():
            for i in range(profile.get('count', 1)):
                vn_fqname = self.get_fqname(name, i)
                self.client_h.delete_network_policy(vn_fqname)
                rules = self._get_rules(profile['rules'], name, i)
                self.client_h.create_network_policy(vn_fqname, rules)

    def exchange_rt(self):
        for name, profile in self.args.networks.items():
            for i in range(profile.get('count', 1)):
                vn_fqname = self.get_fqname(name, i)
                rt = profile['rt_start'] + i
                vn_obj = self.client_h.read_vn(vn_fqname)
                vn_rt = RouteTargetList()
                new_rt = 'target:%s:%s'%(self.asn, rt)
                if new_rt not in vn_rt.route_target:
                    vn_rt.add_route_target(new_rt)
                    vn_obj.set_route_target_list(vn_rt)
                    self.client_h.vnc.virtual_network_update(vn_obj)
        import pdb; pdb.set_trace() #Fix Me - ServiceNetwork
        for name, profile in self.args.networks.items():
            for i in range(profile.get('count', 1)):
                vn_fqname = self.get_fqname(name, i)
                vn_obj = self.client_h.read_vn(vn_fqname)
                vn_rt = RouteTargetList()
                peers = [rule.get('src_vn') or rule.get('dst_vn') for rule in profile['rules']]
                for peer in peers:
                    if peer in self.service_vns:
                        peer_rt = self.args.networks[peer]['rt_start'] + 0
                    else:
                        peer_rt = self.args.networks[peer]['rt_start'] + i
                    rt = 'target:%s:%s'%(self.asn, peer_rt)
                    if rt not in vn_rt.route_target:
                        vn_rt.add_route_target(rt)
                vn_obj.set_import_route_target_list(vn_rt)
                self.client_h.vnc.virtual_network_update(vn_obj)

    def get_migrate_fw_rules(self, name, index):
        rule_list = list()
        rules = self.args.networks[name]['rules']
        if name in self.service_vns:
            min_index = 0
            max_index = self.args.networks[self.app_vns[0]]['count']
        else:
            min_index = index
            max_index = index + 1
        for index in range(min_index, max_index):
            for rule in rules:
                dct = dict()
                dct['dports'] = (rule['port'], rule['port'])
                dct['protocol'] = 'tcp'
                dct['action'] = 'pass'
                if 'dst_vn' in rule:
                    if rule['dst_vn'] in self.service_vns:
                        destination = self.get_fqname(rule['dst_vn'], 0)
                    else:
                        destination = self.get_fqname(rule['dst_vn'], index)
                else:
                    if name in self.service_vns:
                        destination = self.get_fqname(name, 0)
                    else:
                        destination = self.get_fqname(name, index)
                if 'src_vn' in rule:
                    if rule['src_vn'] in self.service_vns:
                        source = self.get_fqname(rule['src_vn'], 0)
                    else:
                        source = self.get_fqname(rule['src_vn'], index)
                else:
                    if name in self.service_vns:
                        source = self.get_fqname(name, 0)
                    else:
                        source = self.get_fqname(name, index)
                dct['source'] = {'virtual_network': ':'.join(source)}
                dct['destination'] = {'virtual_network': ':'.join(destination)}
                rule_list.append(dct)
        return rule_list

    def rollback_migrate_application_networks(self):
        for name, profile in self.args.networks.items():
            if name not in self.app_vns:
                continue
            for i in range(profile.get('count', 1)):
                vn_fqname = self.get_fqname(name, i)
                self.client_h.delete_application_policy_set(self.get_sec_fqname(vn_fqname[-1]))
                self.client_h.delete_firewall_policy(self.get_sec_fqname(vn_fqname[-1]))
                for index in range(len(profile.get('rules', []))):
                    self.client_h.delete_firewall_rule(self.get_sec_fqname(vn_fqname[-1], index))

    def migrate_application_networks(self, index):
        for name, profile in self.args.networks.items():
            if name not in self.app_vns:
                continue
            for i in range(profile.get('count', 1)):
                if index is not None and i != int(index):
                    continue
                vn_fqname = self.get_fqname(name, i)
                self.client_h.check_and_create_tag(vn_fqname[-1:], 'application', vn_fqname[-1])
                self.client_h.set_tag('application', vn_fqname[-1],
                    'virtual_network', vn_fqname)
                rules = self.get_migrate_fw_rules(name, i)
                fw_rules = list()
                for rindex, rule in enumerate(rules):
                    fwr = self.client_h.create_firewall_rule(
                        self.get_sec_fqname(vn_fqname[-1], rindex), **rule)
                    fw_rules.append({'seq_no': rindex, 'uuid': fwr})
                fwp = self.client_h.create_firewall_policy(
                    self.get_sec_fqname(vn_fqname[-1]),
                    rules=fw_rules)
                aps = self.client_h.create_application_policy_set(
                    self.get_sec_fqname(vn_fqname[-1]),
                    policies=[{'uuid': fwp, 'seq_no': 5}])
                self.client_h.set_tag('application', vn_fqname[-1],
                    'application-policy-set',
                     self.get_sec_fqname(vn_fqname[-1]))
        self.migrate_delete_np(index)

    def migrate_service_networks(self, index):
        for name, profile in self.args.networks.items():
            if name not in self.service_vns:
                continue
            for i in range(profile.get('count', 1)):
                if index is not None and i != int(index):
                    continue
                vn_fqname = self.get_fqname(name, i)
                self.client_h.check_and_create_tag(vn_fqname[-1:],
                    'application', vn_fqname[-1])
                self.client_h.set_tag('application', vn_fqname[-1],
                    'virtual_network', vn_fqname)
                rules = self.get_migrate_fw_rules(name, i)
                fw_rules = list()
                for rindex, rule in enumerate(rules):
                    fwr = self.client_h.create_firewall_rule(
                        self.get_sec_fqname(vn_fqname[-1], rindex), **rule)
                    fw_rules.append({'seq_no': rindex, 'uuid': fwr})
                fwp = self.client_h.create_firewall_policy(
                    self.get_sec_fqname(vn_fqname[-1]),
                    rules=fw_rules)
                aps = self.client_h.create_application_policy_set(
                    self.get_sec_fqname(vn_fqname[-1]),
                    policies=[{'uuid': fwp, 'seq_no': 5}])
                self.client_h.set_tag('application', vn_fqname[-1],
                    'application-policy-set',
                     self.get_sec_fqname(vn_fqname[-1]))

    def migrate_delete_service_np(self, index=0):
        for name, profile in self.args.networks.items():
            if name not in self.service_vns:
                continue
            for i in range(profile.get('count', 1)):
                if index is not None and i != int(index):
                    continue
                vn_fqname = self.get_fqname(name, i)
                self.client_h.delete_network_policy(vn_fqname)

    def migrate_delete_np(self, index):
        for name, profile in self.args.networks.items():
            if name not in self.app_vns:
                continue
            for i in range(profile.get('count', 1)):
                if index is not None and i != int(index):
                    continue
                vn_fqname = self.get_fqname(name, i)
                self.client_h.delete_network_policy(vn_fqname)

    def pre_create(self):
        for name, profile in self.args.networks.items():
            for i in range(profile.get('count', 1)):
                vn_fqname = self.get_fqname(name, i)
                self.client_h.create_vn(vn_fqname)
                vn_obj = self.client_h.read_vn(fq_name=vn_fqname)
                port_obj = self.client_h.create_port(vn_fqname, vn_obj)
                self.client_h.create_vm(vn_fqname[-1], port_obj.uuid)
                rules = self._get_rules(profile['rules'], name, i)
                self.client_h.create_network_policy(vn_fqname, rules)

    def pre_delete(self):
        for name, profile in self.args.networks.items():
            for i in range(profile.get('count', 1)):
                vn_fqname = self.get_fqname(name, i)
                self.client_h.delete_vm(vn_fqname)
                self.client_h.delete_network_policy(vn_fqname)
                self.client_h.delete_vn(vn_fqname)

    def create(self):
        for name, profile in self.args.networks.items():
            fn_and_args = self.get_greenlet_args_list(self._create, name, profile)
            greenlets = exec_in_parallel(fn_and_args)
            get_results(greenlets, raise_exception=True)

        if self.use_lr is True:
            for name, profile in self.args.networks.items():
                for i in range(profile['count']):
                    self.create_logical_routers(name, i)
#                else:
#                    self.exchange_route_targets(name, i)

    def _create(self, name, profile, start, end, n_vms, **kwargs):
        count_vms = 0
        for i in range(start, end):
            vn_fqname = self.get_fqname(name, i)
            rt = int(profile['rt_start']) + i
            peer_rt_list = self.get_peer_rt(name, i)
            self.vns[vn_fqname[-1]] = self.client_h.create_vn(
                        vn_fqname, self.asn, rt, peer_rt_list)
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
        if self.use_lr is True:
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

    def create_vn(self, fq_name, asn=None, rt=None, peer_rt_list=None):
        mask = 29
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
        vn_id = self.vnc.virtual_network_create(vn_obj)
        return vn_id

    def read_vn(self, fq_name):
        return self.vnc.virtual_network_read(fq_name=fq_name)

    def delete_vn(self, fq_name):
        try:
            self.vnc.virtual_network_delete(fq_name=fq_name)
        except NoIdError:
            pass

    def create_network_policy(self, fq_name, rules):
        def _get_rule(src_vn, dst_vn, dport):
            src_addr = AddressType(virtual_network=':'.join(src_vn))
            dst_addr = AddressType(virtual_network=':'.join(dst_vn))
            return PolicyRuleType(rule_uuid=str(uuid.uuid4()),
                                  rule_sequence=SequenceType(major=-1, minor=-1),
                                  direction="<>", protocol='tcp',
                                  src_addresses=[src_addr],
                                  dst_addresses=[dst_addr],
                                  dst_ports=[PortType(dport, dport)],
                                  src_ports=[PortType(-1, -1)],
                                  action_list=ActionListType(apply_service=None,
                                                          simple_action='pass'))
        rules_list = list()
        for rule in rules:
            rules_list.append(_get_rule(rule['src_vn'], rule['dst_vn'],
                dport=rule['port']))
        policy = NetworkPolicy(fq_name[-1], parent_type='project',
            fq_name=fq_name,
            network_policy_entries=PolicyEntriesType(rules_list))
        policy_id = self.vnc.network_policy_create(policy)
        network_obj = self.vnc.virtual_network_read(fq_name=fq_name)
        network_obj.add_network_policy(policy,
            VirtualNetworkPolicyType(sequence=SequenceType(major=0, minor=0)))
        self.vnc.virtual_network_update(network_obj)

    def delete_network_policy(self, fq_name):
        try:
            policy_obj = self.vnc.network_policy_read(fq_name=fq_name)
            network_obj = self.vnc.virtual_network_read(fq_name=fq_name)
            network_obj.del_network_policy(policy_obj)
            self.vnc.virtual_network_update(network_obj)
        except NoIdError:
            pass
        try:
            self.vnc.network_policy_delete(fq_name=fq_name)
        except NoIdError:
            pass

#    def exchange_rt(self, vn1_fqname, vn2_fqname):
#        vn1_obj = self.read_vn(vn1_fqname)
#        vn2_obj = self.read_vn(vn2_fqname)
#        vn1_rt = vn1_obj.get_route_target_list().get_route_target()[0]
#        vn2_rt = vn2_obj.get_route_target_list().get_route_target()[0]
#        vn1_import_rt_list = vn1_obj.get_import_route_target_list() or RouteTargetList()
#        vn2_import_rt_list = vn2_obj.get_import_route_target_list() or RouteTargetList()
#        vn1_import_rt_list.add_route_target(vn2_rt)
#        vn2_import_rt_list.add_route_target(vn1_rt)
#        vn1_obj.set_import_route_target_list(vn1_import_rt_list)
#        vn2_obj.set_import_route_target_list(vn2_import_rt_list)
#        self.vnc.virtual_network_update(vn1_obj)
#        self.vnc.virtual_network_update(vn2_obj)

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
            pass

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
        print port_obj.uuid
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
    parser.add_argument('-i', '--index',
                        help='index of the application vn to migrate')
    pargs = parser.parse_args(args)
    return pargs

def main(template, oper, custom_cmd, index):
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
    elif oper.lower() == 'custom':
        obj.custom(custom_cmd)
    elif oper.lower() == 'poll':
        obj.poll_traffic()
    elif oper.lower() == 'stop':
        obj.stop_traffic()
    elif oper.lower() == 'migrate_application_networks':
        obj.migrate_application_networks(index)
    elif oper.lower() == 'migrate_service_networks':
        obj.migrate_service_networks(index)
    elif getattr(obj, oper.lower(), None):
        fn = getattr(obj, oper.lower())
        fn()
    else:
        raise Exception()

if __name__ == '__main__':
    pargs = parse_cli(sys.argv[1:])
    main(pargs.template, pargs.oper, pargs.custom_cmd, pargs.index)
