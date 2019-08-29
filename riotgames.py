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
import gevent

alloc_addr_list = list()

class Scale(object):
    def __init__ (self, args):
        self.client_h = Client(args)
        self.networks = args.networks

    def create(self):
        for network in networks:
            import pdb; pdb.set_trace()           

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

        self.vnc_h = VncApi(username=args.username,
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
        self.vnc.virtual_network_delete(fq_name=fq_name)

    def create_application_policy_set(self, fq_name, policies=None)
        obj = ApplicationPolicySet(fq_name[-1], fq_name=fq_name,
                                   parent_type='policy-management')
        for policy in policies or []:
            policy_obj = self.read_firewall_policy(id=policy['uuid'])
            seq = FirewallSequence(str(policy['seq_no']))
            obj.add_firewall_policy(policy_obj, seq)
        return self.vnc.application_policy_set_create(obj)

    def delete_application_policy_set(self, fq_name):
        return self.vnc.application_policy_set_delete(fq_name=fq_name)

    def create_firewall_policy(self, fq_name, rules=None):
        obj = FirewallPolicy(fq_name[-1], fq_name=fq_name,
                             parent_type='policy-management')
        for rule in rules or []:
            seq = FirewallSequence(str(rule['seq_no']))
            rule_obj = self.read_firewall_rule(id=rule['uuid'])
            obj.add_firewall_rule(rule_obj, seq)
        return self.vnc.firewall_policy_create(obj)

    def delete_firewall_policy(self, fq_name):
        return self.vnc.firewall_policy_delete(fq_name=fq_name)

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
            direction=None,
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
        if match:
            match = FirewallRuleMatchTagsType(tag_list=match)
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
        return self.vnc.firewall_rule_delete(fq_name=fq_name)

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

    def delete_tag(self, fq_name):
        return self.vnc.tag_delete(fq_name=fq_name)

    def read_tag(self, **kwargs):
        return self.vnc.tag_read(**kwargs)

    def _get_obj(self, object_type, fq_name):
        api = ('self._vnc.' + object_type + '_read').replace('-', '_')
        return eval(api)(fq_name=fq_name)

    def set_tag(self, tag_type, tag_value, object_type, fq_name):
        obj = self._get_obj(object_type, fq_name)
        return self.vnc.set_tag(obj, tag_type, tag_value, True)

    def unset_tag(self, tag_type, object_type, fq_name):
        obj = self._get_obj(object_type, fq_name)
        return self.vnc.unset_tag(obj, tag_type)

    def create_port(self, fq_name, vn_obj, device_owner=None):
        port_obj = VirtualMachineInterface(fq_name[-1],
            fq_name=fq_name, parent_type='project')
        port_obj.add_virtual_network(vn_obj)
        self.vnc.virtual_machine_interface_create(port_obj)
        iip_obj = InstanceIp(name=fq_name[-1])
        iip_obj.add_virtual_network(vn_obj)
        iip_obj.add_virtual_machine_interface(port_obj)
        self.vnc.instance_ip_create(iip_obj)
        return port_obj

    def delete_port(self, fq_name):
        self.vnc.instance_ip_delete(fq_name=fq_name)
        self.vnc.virtual_machine_interfac_deletee(fq_name=fq_name)

    def read_port(self, **kwargs):
        return self.vnc.virtual_machine_interface_read(**kwargs)

    def create_router(self, fq_name, vns):
        obj = LogicalRouter(name=fq_name[-1], parent_type='project',
                            fq_name=fq_name,
                            logical_router_type='snat-routing')
        for vn in vns:
            import pdb; pdb.set_trace()
            vn_obj = self.read_vn(fq_name=vn)
            ipam_refs = vn_obj.get_network_ipam_refs()
            for ipam_ref in ipam_refs or []:
                subnet = ipam_ref['attr'].get_ipam_subnets()[0]
                gateway = subnet.default_gateway
                break
            port_fq_name = vn_obj.fq_name
            port_fq_name[-1] = port_fq_name[-1]+'-rtr-vmi'
            port_obj = self.create_port(fq_name=port_fq_name,
                vn=vn_obj, device_owner="network:router_interface")
            obj.add_virtual_machine_interface(port_obj)
        uuid = self.vnc.logical_router_create(obj)
        return uuid

    def delete_router(self, fq_name, vns):
        for vn in vns:
            import pdb; pdb.set_trace()
            vn_obj = self.read_vn(fq_name=vn)
            port_fq_name = vn_obj.fq_name
            port_fq_name[-1] = port_fq_name[-1]+'-rtr-vmi'
            #obj.add_virtual_machine_interface(port_obj)
            self.delete_port(fq_name=fq_name)
        self.vnc.logical_router_delete(fq_name=fq_name)

    def create_vm(self, vm_name, vn_uuid):
        nics = [{'net-id': vn_uuid}]
        response = self.nova.servers.create(name=vm_name,
                                            flavor=self.flavor,
                                            image=self.image,
                                            nics=nics)

    def delete_vm(self, vm_name):
        import pdb; pdb.set_trace()
        self.nova.servers.delete(name=vm_name)
#    def delete_vm(self, vm_obj):
#        vm_obj.delete()

    def get_vm_by_id(self, vm_id):
        return self.nova.servers.get(vm_id)

    def get_vmi_ip(self, **kwargs):
        vmi_obj = self.read_port(**kwargs)
        for iip in vmi_obj.get_instance_ip_back_refs() or []:
            iip_obj = self.vnc.instance_ip_read(id=iip['uuid'])
            return iip_obj.instance_ip_address

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
    else:
        raise Exception()

if __name__ == '__main__':
    pargs = parse_cli(sys.argv[1:])
    import pdb; pdb.set_trace()
    main(pargs.template, pargs.oper)
