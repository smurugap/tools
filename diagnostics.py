import re
import os
import sys
import argparse
from lxml import etree
from vnc_api.vnc_api import *
from collections import defaultdict
from fabric.api import run
from fabric.context_managers import settings
try:
    from neutronclient.neutron import client as neutron_client
    from novaclient import client as nova_client
    from keystoneclient.v2_0 import client as ks_client
except:
    pass

defaults = {'keystone_ip': '127.0.0.1',
            'orch_username': 'admin',
            'orch_password': 'contrail123',
            'tenant': 'admin',
            'region': 'regionOne',
            'host_username': 'root',
            'host_password': 'c0ntrail123',
            'vm_username': 'ubuntu',
            'vm_password': 'ubuntu',
           }
user_inputs = ('keystone_ip', 'orch_username', 'orch_password',
               'tenant', 'host_username', 'host_password',
               'vm_id', 'vm_username', 'vm_password', 'destination')
host_name_map = dict()

class log(object):
    def __init__(self, cls):
        self.cls = cls
    def logger(self, message):
        prefix = self.cls.__class__.__name__
        if getattr(self.cls, 'ip', None):
            prefix = prefix+':'+self.cls.ip
        print prefix+':', message

class orch(object):
    def __init__(self, args):
        super(orch, self).__init__()
        self.args = args
        self.get_handle()
        self.hosts = dict()
        self.vm_obj = dict()
        self.vn_obj = dict()
        self.log = log(self).logger

class openstack(orch):
    def get_handle(self):
        port = 35357
        self.auth_url = 'http://%s:%d/v2.0' %(self.args.keystone_ip, port)
        self.keystone = ks_client.Client(username=self.args.orch_username,
                                         password=self.args.orch_password,
                                         tenant_name=self.args.tenant,
                                         auth_url=self.auth_url,
                                         insecure=True)
        self.auth_token = self.keystone.auth_token

    def get_auth_token(self):
        return self.auth_token

    def connect_network(self):
        self.neutron = neutron_client.Client('2.0',
                                             auth_url=self.auth_url,
                                             username=self.args.orch_username,
                                             password=self.args.orch_password,
                                             tenant_name=self.args.tenant,
                                             insecure=True)

    def connect_compute(self):
        if not getattr(self, 'nova', None):
            self.nova = nova_client.Client('2',
                                    auth_url=self.auth_url,
                                    username=self.args.orch_username,
                                    api_key=self.args.orch_password,
                                    project_id=self.args.tenant,
                                    auth_token=self.auth_token,
                                    insecure=True)
        return self.nova

    def build(self):
        pattern="http://(?P<ip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})(:(?P<port>\d+))?"
        services = ('network', 'compute')
        for service in services:
            uris = self.keystone.service_catalog.get_endpoints(service)[service]
            self.hosts[service] = [re.match(pattern, x['publicURL']).group('ip') for x in uris]
        self.hosts['agent'] = self.get_hypervisor_list()
        return self.hosts

    def get_hypervisor_list(self):
        global host_name_map
        self.connect_compute()
        hosts = list()
        for host_info in self.nova.hypervisors.list(detailed=True):
            hosts.append(host_info.host_ip)
            host_name_map[host_info.hypervisor_hostname] = host_info.host_ip
        return hosts

    def get_vm_obj(self, vm_id):
        if vm_id not in self.vm_obj:
            self.vm_obj[vm_id] = self.nova.servers.get(vm_id)
        return self.vm_obj[vm_id]

    def get_vm_name(self, vm_id):
        vm_obj = self.get_vm_obj(vm_id)
        return vm_obj.name

    def get_host_of_vm(self, vm_id):
        vm_obj = self.get_vm_obj(vm_id)
        return host_name_map[vm_obj._info['OS-EXT-SRV-ATTR:hypervisor_hostname']]

    def get_vm_ips(self, vm_id):
        vm_obj = self.get_vm_obj(vm_id)
        assigned_ips = list()
        for vn,ips in vm_obj._info['addresses'].iteritems():
            for ip in ips:
                assigned_ips.append(ip['addr'])
        return assigned_ips

    def get_vn_ids(self, vm_id):
        vn_names = self.get_vm_obj(vm_id).addresses.keys()
        vn_objs = self.neutron.list_networks(name=vn_names)['networks']
        for vn_obj in vn_objs:
            self.vn_obj[vn_obj['id']] = vn_obj
        return [vn_obj['id'] for vn_obj in self.vn_obj.itervalues() if vn_obj['name'] in vn_names]

    def get_vn_obj(self, vn_id):
        if vn_id not in self.vn_obj:
            self.vn_obj[vn_id] = self.neutron.show_network(vn_id)['network']
        return self.vn_obj[vn_id]

    def verify_vm_is_up(self, vm_id):
        vm_obj = self.get_vm_obj(vm_id)
        if vm_obj._info['status'].lower() == 'active' and \
           vm_obj._info['OS-EXT-STS:power_state'] == 1:
            self.log("VM got launched")
        else:
            self.log("VM is not launched")

    def verify_ip_assigned(self, vm_id):
        vm_ips = self.get_vm_ips(vm_id)
        if vm_ips:
            self.log('VM %s has been assigned %s'%(vm_id, str(vm_ips)))
        else:
            self.log('VM hasnt been assigned an ip address')

    def verify_vm(self, vm_id):
        self.verify_vm_is_up(vm_id)
        self.verify_ip_assigned(vm_id)
        return True

class JsonDrv(object):
    def __init__(self, auth_token=None):
        self._headers = None
        if auth_token:
            self._headers = {'X-AUTH-TOKEN': auth_token}

    def load(self, url):
        resp = requests.get(url, headers=self._headers)
        if resp.status_code == 200:
            return json.loads(resp.text)
        return None

class XmlDrv(object):
    def load(self, url):
        return etree.fromstring(requests.get(url).text)

class inspect(object):
    def __init__(self, ip, port, drv=JsonDrv, **kwargs):
        super(inspect, self).__init__()
        self.ip = ip
        self.port = int(port)
        self.drv = drv(**kwargs)
        self.log = log(self).logger

    def _mk_url_str(self, path=''):
        if path.startswith('http:'):
            return path
        return "http://%s:%d/%s" % (self.ip, self.port, path)

    def http_get(self, path):
        return self.drv.load(self._mk_url_str(path))

    def get_path(self, obj_type, **kwargs):
        raise NotImplementedError

    def process_response(self, resp, **kwargs):
        return resp

    def elem2dict(self, node, alist=False):
        d = list() if alist else dict()
        for e in node.iterchildren():
            #key = e.tag.split('}')[1] if '}' in e.tag else e.tag
            if e.tag == 'list':
                value = self.elem2dict(e, alist=True)
            else:
                value = e.text if e.text else self.elem2dict(e)
            if type(d) == type(list()):
                d.append(value)
            else:
                d[e.tag] = value
        return d

    def get(self, obj_type, obj_id, match=None, **kwargs):
        if not getattr(self, obj_type+'_obj', None):
            setattr(self, obj_type+'_obj', dict())
        obj = getattr(self, obj_type+'_obj')
        if obj_id in obj:
            return obj[obj_id]
        resp = self.http_get(self.get_path(obj_type=obj_type, obj_id=obj_id, **kwargs))
        obj[obj_id] = self.process_response(resp, obj_type=obj_type, obj_id=obj_id, match=match)
        return obj[obj_id]

class discovery(inspect):
    def __init__(self, disc_ip):
        port = 5998
        super(discovery, self).__init__(disc_ip, port)

    def get_services(self):
        services = {'xmpp-server': 'control-node',
                    'OpServer': 'analytics',
                    'ApiServer': 'config'}
        service_dict = defaultdict(list)
        for service in self.http_get('services.json')['services']:
            svc_type = services.get(service['service_type'], None)
            if not svc_type:
                continue
            service_dict[svc_type].append(service['info'])
        return service_dict

class agent(inspect):
    obj_path = {'vmi': 'Snh_PageReq?x=begin:-1,end:-1,table:db.interface.0',
                'vn': 'Snh_PageReq?x=begin:-1,end:-1,table:db.vn.0',
               }
    xml_path = {'vn': './VnListResp/vn_list/list/VnSandeshData',
                'vmi': './ItfResp/itf_list/list/ItfSandeshData',
                'v4': './Inet4UcRouteResp/route_list/list/RouteUcSandeshData',
               }
    def __init__(self, ip):
        port = 8085
        super(agent, self).__init__(ip, port, drv=XmlDrv)
        self.vrf_obj = dict()

    def get_path(self, obj_type, **kwargs):
        return self.obj_path[obj_type]

    def process_response(self, xml, obj_type, obj_id=None, match=None):
        obj_list = list()
        if not match:
            match = 'uuid'
        elements = xml.xpath(self.xml_path[obj_type])
        for element in elements:
            obj_list.append(self.elem2dict(element))
        if obj_id:
            for obj in obj_list:
                if obj.get(match, None) == obj_id:
                    return obj
            else:
                return None
        return obj_list

    def get_active_control_node(self):
        response = self.http_get('Snh_AgentXmppConnectionStatusReq?')
        for node in response.xpath('./peer/list/AgentXmppData'):
            if node.find('cfg_controller').text.lower() == 'yes':
                return node.find('controller_ip').text
        raise

    def get_vmi(self, vmi_id, field=None):
        vmi = self.get('vmi', vmi_id)
        return vmi[field] if field else vmi

    def verify_vmi_links(self, vmi_id, ri_name, address):
        if self.get_vmi(vmi_id, 'vrf_name') != ri_name:
            self.log('VMI doesnt have link to vrf')
        else:
            self.log('VMI has vrf set')
        if self.get_vmi(vmi_id, 'ip_addr') in address:
            self.log('VMI has ip address set')
        else:
            self.log('VMI doesnt have ip address set')

    def fetch_routes(self, vrf, af='v4'):
        rt_dict = {'v4': 'uc.route.0', 'v6': 'uc.route6.0',
                   'evpn': 'evpn.route.0', 'l2': 'l2.route.0'}
        if vrf+af in self.vrf_obj:
            return self.vrf_obj[vrf+af]
        xml = self.http_get('Snh_PageReq?x=begin:-1,end:-1,table:%s.%s'%(vrf,rt_dict[af]))
        self.vrf_obj[vrf+af] = xml
        return self.process_response(xml, af)

    def get_matching_routes(self, vrf_name, prefix, plen, af):
        routes = self.fetch_routes(vrf_name, af)
        for route in routes:
            if route['src_ip'] == prefix and route['src_plen'] == str(plen):
                return route['path_list']['list']
        else:
            self.log('Unable to find route with prefix %s and plen %s in vrf'%(prefix, str(plen)), vrf_name)
            return []

    def verify_prefix(self, vrf_name, prefix, label, nh_type, nh_value):
        for path in self.get_matching_routes(vrf_name, prefix, plen=32, af='v4'):
            if path['label'] == label and path['nh']['NhSandeshData'][nh_type] == nh_value:
                self.log('Route for prefix %s found with label %s'%(prefix, label))
                return True
        else:
            self.log('Route for prefix %s doesnt exist or has wrong index %s'%(prefix, label))
            return False

    def verify_vm(self, vm_id, vmis):
        for vmi_id,vmi_obj in vmis.iteritems():
            ri = self.get('vn', vmi_obj['vn'][0]['uuid'])
            if ri and ri['vrf_name'] == ':'.join(vmi_obj['ri'][0]['to']):
                self.log('VN has link to RI')
            else:
                self.log('VN doesnt have link to RI')
            self.verify_vmi_links(vmi_id, ri['vrf_name'], vmi_obj['ip'])
            intf = self.get_vmi(vmi_id, 'name')
            label = self.get_vmi(vmi_id, 'label')
            for prefix in vmi_obj['ip']:
                self.log('Verifying prefix %s with label %s and nh %s in vrf %s'%(prefix, label, intf, ri['vrf_name']))
                self.verify_prefix(ri['vrf_name'], prefix, label, nh_type='itf', nh_value=intf)

class control(inspect):
    obj_path = {'rt': 'Snh_ShowRouteReq?x='}
    xml_path = {'rt': './tables/list/ShowRouteTable'}
    def __init__(self, ip):
        port = 8083
        super(control, self).__init__(ip, port, drv=XmlDrv)
        self.vrf_obj = dict()

    def get_path(self, obj_type, obj_id, **kwargs):
        return self.obj_path[obj_type]+obj_id

    def process_response(self, xml, obj_type, obj_id=None, match=None):
        obj_list = list()
        if not match:
            match = 'uuid'
        elements = xml.xpath(self.xml_path[obj_type])
        for element in elements:
            obj_list.append(self.elem2dict(element))
        if obj_id:
            for obj in obj_list:
                if obj.get(match, None) == obj_id:
                    return obj
            else:
                return None
        return obj_list

    def get_matching_routes(self, vrf_name, prefix, plen, af):
        rt_dict = {'v4': '.inet.0', 'v6': '.inet6.0',
                   'evpn': '.evpn.0'}
        routes = self.get('rt', vrf_name+rt_dict[af], match='routing_table_name')['routes']['list']
        for route in routes:
            if route['prefix'] == prefix+'/'+str(plen):
                return route['paths']['list']
        else:
            return []

    def verify_prefix(self, vrf_name, prefix, label, nh_type, nh_value):
        for path in self.get_matching_routes(vrf_name, prefix, plen=32, af='v4'):
            if path['label'] == label and path[nh_type] == nh_value:
                self.log('Route for prefix %s found with label %s'%(prefix, label))
                return True
        else:
            self.log('Route for prefix %s doesnt exist or has wrong index %s or nh'%(prefix, label))
            return False

    def verify_vm(self, vm_id, vmis, agent):
        for vmi_id,vmi_obj in vmis.iteritems():
            vrf = ':'.join(vmi_obj['ri'][0]['to'])
            for prefix in vmi_obj['ip']:
                self.log('Verifying prefix %s with label %s and nh %s in vrf %s'%(prefix, vmi_obj['label'], agent, vrf))
                self.verify_prefix(vrf, prefix, vmi_obj['label'], 'next_hop', agent)

class config(inspect):
    obj_path = {'vm': 'virtual-machine',
            'vmi': 'virtual-machine-interface',
            'iip': 'instance-ip',
            'vn': 'virtual-network',
            'ri': 'routing-instance',
           }
    def __init__(self, ip, auth_token=None):
        port = 9100
        super(config, self).__init__(ip, port, auth_token=auth_token)
        self.port_obj = defaultdict(dict)

    def get_path(self, obj_type, obj_id, **kwargs):
        return self.obj_path[obj_type]+'/'+obj_id

    def process_response(self, resp, obj_type, **kwargs):
        return resp[self.obj_path[obj_type]]

    def get_vmis(self, vm_id):
        vmis = [vmi['uuid'] for vmi in self.get('vm', vm_id)['virtual_machine_interface_back_refs']]
        return [self.get('vmi', vmi) for vmi in vmis]

    def get_ip_address(self, vmi_id):
        if vmi_id not in self.vmi_obj:
            self.get('vmi', vmi_id)
        iips = [iip['uuid'] for iip in self.vmi_obj[vmi_id]['instance_ip_back_refs']]
        return [self.get('iip', iip)['instance_ip_address'] for iip in iips]

    def verify_ip_assigned(self, vm_id, expected_ips=[]):
        assigned_ips = list()
        vmis = self.get_vmis(vm_id)
        for vmi in vmis:
            assigned_ips.extend(self.get_ip_address(vmi['uuid']))
        if assigned_ips and (not expected_ips or set(expected_ips) == set(assigned_ips)):
            self.log('VM have IP address assigned')
        else:
            self.log('VM doesnt have expected IP address, expected %s, assigned %s' %(expected_ips, assigned_ips))

    def verify_ri_links(self, vm_id, expected_ris=[]):
        assigned_ris = list()
        vmis = self.get_vmis(vm_id)
        for vmi in vmis:
            ris = [ri['uuid'] for ri in vmi['routing_instance_refs']]
            assigned_ris.extend([':'.join(self.get('ri', ri)['fq_name']) for ri in ris])
        if assigned_ris and (not expected_ris or set(expected_ris) == set(assigned_ris)):
            self.log('VMI have RI link')
        else:
            self.log('VMI doesnt have RI refs')

    def verify_vn_links(self, vm_id, expected_vns=[]):
        assigned_vns = list()
        vmis = self.get_vmis(vm_id)
        for vmi in vmis:
            vns = [vn['uuid'] for vn in vmi['virtual_network_refs']]
            assigned_vns.extend([':'.join(self.get('vn', vn)['fq_name']) for vn in vns])
        if assigned_vns and (not expected_vns or set(expected_vns) == set(assigned_vns)):
            self.log('VMI have link to VN')
        else:
            self.log('VMI doesnt have VN refs')

    def get_port_obj(self, vmi_id):
        self.port_obj[vmi_id['uuid']]['vn'] = vmi_id['virtual_network_refs']
        self.port_obj[vmi_id['uuid']]['ri'] = vmi_id['routing_instance_refs']
        self.port_obj[vmi_id['uuid']]['ip'] = self.get_ip_address(vmi_id['uuid'])
        return self.port_obj[vmi_id['uuid']]

    def get_port_mappings(self, vm_id):
        vmis = self.get_vmis(vm_id)
        port_objs = dict()
        for vmi in vmis:
            port_objs[vmi['uuid']] = self.get_port_obj(vmi)
        return port_objs

class host(object):
    def __init__(self, host_ip, host_username, host_password):
        self.host_string = '%s@%s'%(host_username, host_ip)
        self.host_password = host_password

    def run_cmd_on_host(self, cmds):
        output = dict()
        with settings(host_string=self.host_string, password=self.host_password,
                      warn_only=True, abort_on_prompts=False):
            for cmd in cmds:
                output[cmd] = run(cmd)
        return output

    def run_cmd_on_vm(self, cmd, local_ip, vm_username, vm_password):
        fab_string = 'fab -H %s@%s -p %s -- '%(vm_username, local_ip, vm_password)
        host_cmd = fab_string+'"'+cmd+'"'
        return self.run_cmd_on_host([host_cmd])[host_cmd]

class contrail(object):
    def __init__(self, discovery_ip='127.0.0.1', auth_h=None,
                 username=None, password=None):
        self.discovery = discovery(discovery_ip)
        self.hosts = dict(); self.ports = dict()
        self.auth = auth_h
        self.args = self.auth.args
        self.log = log(self).logger

    def build(self):
        services = self.discovery.get_services()
        for service in services.keys():
            for svc_info in services[service]:
                if service not in self.hosts:
                    self.hosts[service] = list()
                    self.ports[service] = list()
                self.hosts[service].append(svc_info['ip-address'])
                self.ports[service].append(svc_info['port'])
        return self.hosts

    def connect(self):
        self.agent = dict(); self.control = dict()
        self.config = dict()
        for host in self.hosts['agent']:
            self.agent[host] = agent(host)
        for host in self.hosts['control-node']:
            self.control[host] = control(host)
        for host in self.hosts['config']:
            self.config[host] = config(host, self.auth.get_auth_token())

    def get_host_handle(self, host_ip):
        if host_ip not in self.hosts:
            self.hosts[host_ip] = host(host_ip, self.args.host_username,
                                       self.args.host_password)
        return self.hosts[host_ip]

    def get_host_of_vm(self, vm_id):
        return self.auth.get_host_of_vm(vm_id)

    def check_linklocal_ip(self, host_ip, local_ip):
        host_h = self.get_host_handle(host_ip)
        cmd = 'ping -c 2 %s'%local_ip
        output = host_h.run_cmd_on_host([cmd])[cmd]
        if '100% packet loss' in output:
            return False
        return True

    def get_link_local_ip(self, vm_id):
        agent_host = self.auth.get_host_of_vm(vm_id)
        local_ips = list()
        config = self.config.values()[0]
        for vmi in config.get_vmis(vm_id):
            local_ips.append(self.agent[agent_host].get_vmi(vmi['uuid'], 'mdata_ip_addr'))
        for local_ip in local_ips:
            if self.check_linklocal_ip(agent_host, local_ip):
                return local_ip

    def verify_vm(self, vm_id):
        vn_ids = self.auth.get_vn_ids(vm_id)
        vm_ips = self.auth.get_vm_ips(vm_id)
        vn_fq_names = [self.auth.get_vn_obj(vn_id)['contrail:fq_name'] for vn_id in vn_ids]
        ri_names = [':'.join(vn+vn[-1:]) for vn in vn_fq_names]

        # Check on config node
        for config in self.config.values():
            config.verify_vn_links(vm_id, [':'.join(vn) for vn in vn_fq_names])
            config.verify_ip_assigned(vm_id, vm_ips)
            config.verify_ri_links(vm_id, ri_names)
        port_objs = config.get_port_mappings(vm_id)

        # Checks on agent
        agent_host = self.get_host_of_vm(vm_id)
        self.agent[agent_host].verify_vm(vm_id, port_objs)
        for vmi_id, port_obj in port_objs.iteritems():
            port_obj['label'] = self.agent[agent_host].get_vmi(vmi_id, 'label')

        # Check on Controller
        control_host = self.agent[agent_host].get_active_control_node()
        self.control[control_host].verify_vm(vm_id, port_objs, agent_host)
        return True

    def verify_vdns(self, vm_id, destination):
        destination = destination if destination else self.auth.get_vm_name(vm_id)
        return self.ping(vm_id, destination)

    def ping(self, vm_id, destination):
        cmd = 'ping -c 2 '+destination
        local_ip = self.get_link_local_ip(vm_id)
        host_h = self.get_host_handle(self.auth.get_host_of_vm(vm_id))
        output = host_h.run_cmd_on_vm(cmd, local_ip,
                                      self.args.vm_username,
                                      self.args.vm_password)
        if ' 0% packet loss' in output:
            self.log('Ping works fine from %s to %s'%(vm_id, destination))
            return True
        self.log('Ping to %s failed from vm_id %s'%(destination, vm_id))
        return False

    def verify_fip(self, vm_id, floatingip):
        return self.ping(vm_id, floatingip)

class connections(object):
    def __init__(self, args):
        self.args = args
        self.build()
        self.connect()

    def build(self):
        self.auth = openstack(self.args)
        orch_hosts = self.auth.build()
        self.contrail = contrail(orch_hosts['network'][0], auth_h=self.auth)
        #ToDo: Need to get rid of the hacks
        self.contrail.build().update(orch_hosts)

    def connect(self):
        self.auth.connect_network()
        self.auth.connect_compute()
        self.contrail.connect()

class Struct(object):
    def __init__(self, entries):
        self.__dict__.update(entries)

def parse_args(argv):
    def parse_cli():
        parser = argparse.ArgumentParser(description=__doc__)
        for var in user_inputs:
            parser.add_argument('--'+var, help=None)
        return dict(parser.parse_args(argv)._get_kwargs())
    def build_args(cli_args):
        args = dict()
        for var in user_inputs:
            args[var] = cli_args.get(var, None) or os.getenv(var) or defaults.get(var, None)
        return args
    return Struct(build_args(parse_cli()))

def verify_vm(connections, vm_id):
    connections.auth.verify_vm(vm_id), 'VM verification on Orchestrator failed'
    connections.contrail.verify_vm(vm_id), 'VM verification failed'

def verify_vdns(connections, vm_id, destination):
    connections.contrail.verify_vdns(vm_id, destination)

def verify_fip(connections, vm_id, floatingip):
    connections.contrail.verify_fip(vm_id, floatingip)

def main():
    pargs = parse_args(sys.argv[1:])
    conn = connections(pargs)
    verify_vm(conn, pargs.vm_id)
    verify_vdns(conn, pargs.vm_id, pargs.destination)
    if pargs.destination:
        verify_fip(conn, pargs.vm_id, pargs.destination)

if __name__ == '__main__':
    main()
