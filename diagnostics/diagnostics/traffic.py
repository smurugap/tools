import sys
import string
import argparse
from tcutils.cfgparser import parse_cfg_file
from common.contrail_test_init import ContrailTestInit
from common.connections import ContrailConnections
from tcutils.db import TestDB
from config import *

def random_string(prefix):
    return prefix+''.join(random.choice(string.hexdigits) for _ in range(6))

def sig_handler(_signo, _stack_frame):
    raise KeyboardInterrupt

def setup_test_infra(testbed_file):
    import logging
    from common.log_orig import ContrailLogger
    logging.getLogger('urllib3.connectionpool').setLevel(logging.WARN)
    logging.getLogger('paramiko.transport').setLevel(logging.WARN)
    logging.getLogger('keystoneclient.session').setLevel(logging.WARN)
    logging.getLogger('keystoneclient.httpclient').setLevel(logging.WARN)
    logging.getLogger('neutronclient.client').setLevel(logging.WARN)
    logger = ContrailLogger('traffic')
    logger.setUp()
    mylogger = logger.logger
    inputs = ContrailTestInit(testbed_file, logger=mylogger)
    inputs.setUp()
    connections = ContrailConnections(inputs=inputs, logger=mylogger)
    return connections

class traffic(object):
    def __init__(self, args):
        self.args = args
        self.connections = setup_test_infra(args.testbed_file)
        self.db = TestDB(args.db_file) if args.db_file else None

    def get_tenant_fqnames(self):
        if self.args.tenant:
            return [':'.join([self.connections.inputs.domain_name, self.args.tenant])]
        if self.db:
            return self.db.list_projects()
        return []

    def get_vn_ids(self, project_fqname, connections):
        if self.args.vn_name:
            vn_id = connections.get_network_h().get_vn_id(self.args.vn_name)
            assert vn_id, 'Unable to fetch ID of vn_name '+ self.args.vn_name
            return [vn_id]
        vns = []
        if self.db:
            for fqname in self.db.list_virtual_networks(project_fqname):
                (vn_id, vn_subnet) = self.db.get_virtual_network(fqname)
                vns.append(vn_id)
        return vns

    def get_fip_pools(self):
        if self.db:
            return self.db.list_fip_pools()
        return []

    def get_fip_from_id(self, fip_id):
        return FloatingIPPool(self.connections).get_fip_from_id(fip_id)

    def get_all_fips(self):
        fips = []
        if self.args.fip_pool_id:
            for fip_pool_id in self.args.fip_pool_id:
                obj = FloatingIPPool(self.connections)
                for fip_id in obj.get_associated_fips(fip_pool_id):
                    fips.append(self.get_fip_from_id(fip_id))
        elif self.db:
            for fip_pool_fqname in self.get_fip_pools():
                fip_pool_id = self.db.get_fip_pool_id(fip_pool_fqname)
                for fip_id in self.db.get_fips(fip_pool_fqname):
                    fips.append(self.get_fip_from_id(fip_id))
        return fips

    def get_vm_details(self, vm_ids, vn_name, connections):
        vm_names = []
        vm_ips = []
        for vm_id in vm_ids:
            vm_obj = VM(connections)
            vm_names.append(vm_obj.vm_name(vm_id))
            vm_ips.append(vm_obj.vm_ip(vm_id, vn_name))
        return (vm_ips, vm_names)

    def get_vm_in_vns(self, vn_id, tenant_fqname):
        if self.db:
            return self.db.list_vms_in_vn(vn_id, tenant_fqname)
        return []

    def get_creds(self, vm_id, tenant_fqname):
        if self.args.username and self.args.password:
            return (self.args.username, self.args.password)
        if self.db:
            return self.db.get_creds_of_vm(vm_id, tenant_fqname)
        return (None, None)

    def get_project_id(self, fqname):
        if self.db:
            return self.db.get_project_id(fqname)
        else:
            return self.connections.get_auth_h().get_project_id(fqname[-1])

    def verify(self):
        svm_id = self.args.vm_id
        destination = self.args.destination
        for tenant_fqname in self.get_tenant_fqnames():
            project_id = self.get_project_id(tenant_fqname)
            project_obj = Project(self.connections)
            connections = project_obj.get_connections(project_id)

            if not self.args.destination:
                fips = self.get_all_fips()

            for vn_id in self.get_vn_ids(tenant_fqname, connections):
                vn_obj = VN(connections)
                vn_name = vn_obj.get_fixture(vn_id).get_name()
                if not self.args.destination or not svm_id:
                    vm_ids = self.get_vm_in_vns(vn_id, tenant_fqname)
                    if not vm_ids:
                        print 'No vms associated with the VN', vn_id
                        continue
                    svm_id = vm_ids[0]

                # Find destination IP
                if not self.args.destination:
                    dvm_ids = vm_ids[1:]
                    (dvm_ips, dvm_names) = self.get_vm_details(dvm_ids, vn_name,
                                                               connections)
                if self.args.test_vdns:
                    destination = dvm_names
                else:
#ToDo: msenthil - control adding fips to destination
                    destination = dvm_ips + fips

                svm_obj = VM(connections)
                (svm_username, svm_password) = self.get_creds(svm_id, tenant_fqname)
                for dst in list(set(destination)):
                    if self.args.proto.lower() == 'icmp':
                        assert svm_obj.ping(svm_id, dst, svm_username, svm_password)
                    elif self.args.proto.lower() == 'tcp':
                        assert svm_obj.tcpecho(svm_id, dst,
                                               username=svm_username,
                                               password=svm_password)

def validate_args(args):
    for key, value in args.__dict__.iteritems():
        if value == 'None':
            args.__dict__[key] = None
        if value == 'False':
            args.__dict__[key] = False
        if value == 'True':
            args.__dict__[key] = True

    if (args.vm_id or args.vn_name) and not args.tenant:
        raise Exception('Need tenant name too. use --tenant <tenant_name>')
    if args.vm_id and not (args.username and args.password):
        raise Exception('Need VM username and password')
    if not args.testbed_file:
        args.testbed_file = os.path.join(os.path.abspath(
                                         os.path.dirname(__file__)),
                                         '../', 'sanity_params.ini')
    if not args.db_file:
        args.db_file = os.path.join('/var/tmp/', 'test.db')
    if type(args.fip_pool_id) is str:
       args.fip_pool_id = [args.fip_pool_id]
    if not args.proto:
        args.proto = 'icmp'

def parse_cli(args):
    '''Define and Parse arguments for the script'''
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--testbed_file', default=None,
                        help='Specify testbed ini file', metavar="FILE")
    parser.add_argument('--db_file', default=None,
                        help='Specify database file', metavar="FILE")

    parser.add_argument('--tenant', default=None,
                        help='Tenant name []')
    parser.add_argument('--vn_name', default=None,
                        help='Name of virtual network')
    parser.add_argument('--vm_id', default=None,
                        help='UUID of Virtual Machine')
    parser.add_argument('--fip_pool_id', default=None,
                        help='UUID of Floating IP Pool')
    parser.add_argument('--username', default=None,
                        help='VM username - required if vm_id is specified')
    parser.add_argument('--password', default=None,
                        help='VM password - required if vm_id is specified')

    parser.add_argument('--destination', default=None,
                        help='Destination IP of the traffic')
    parser.add_argument('--dport', default=None,
                        help='Destination port of the traffic')
    parser.add_argument('--proto', default=None,
                        help='L3 Protocol (icmp or tcp)')
    parser.add_argument('--test_vdns', action='store_true',
                        help='Test vdns(within the same VN)')
    return dict(parser.parse_known_args(args)[0]._get_kwargs())

def update_args(ini_args, cli_args):
    for key in cli_args.keys():
        if cli_args[key]:
            ini_args[key] = cli_args[key]
    return ini_args

class Struct(object):
    def __init__(self, entries):
        self.__dict__.update(entries)

def main():
    signal.signal(signal.SIGTERM, sig_handler)
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-i", "--ini_file", help="Specify conf file", metavar="FILE")
    args, remaining_argv = parser.parse_known_args(sys.argv[1:])
    cli_args = parse_cli(remaining_argv)
    if args.ini_file:
        ini_args = parse_cfg_file(args.ini_file)
        args = update_args(ini_args['TEST'], cli_args)
        args.update(update_args(ini_args['Traffic'], cli_args))
        args.update(update_args(ini_args['DEFAULTS'], cli_args))
    else:
        args = cli_args
    args = Struct(args)
    validate_args(args)
    obj = traffic(args)
    obj.verify()

if __name__ == "__main__":
    main()
