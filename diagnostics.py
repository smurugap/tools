from multiprocessing import Process
import os
import sys
from vnc_api.vnc_api import *
try:
    from neutronclient.neutron import client as neutron_client
    from novaclient import client as nova_client
    from keystoneclient.v2_0 import client as ks_client
except:
    pass

defaults = {'keystone_ip': '127.0.0.1',
            'admin_user': 'admin',
            'admin_password': 'contrail123',
            'admin_tenant': 'admin',
            'region': 'regionOne',
            'sudo_user': 'root',
            'sudo_password': 'c0ntrail123',
           } 
user_inputs = ('keystone_ip', 'admin_user', 'admin_password',
               'admin_tenant', 'sudo_user', 'sudo_password')

class orch(object):
    def __init__(self, args):
        self.args = args
        self.get_handle()

class openstack(orch):
    def get_handle(self):
        auth_url = 'http://%s:35357/v2.0' % self.args.keystone_ip
        self.auth = ks_client.Client(username=self.args.admin_user,
                                     password=self.args.admin_password,
                                     tenant_name=self.args.admin_tenant,
                                     auth_url=auth_url,
                                     insecure=True)
        self.auth_token = self.auth.auth_token

    def get_endpoints(self):
        services = ('network', 'compute')

class discovery(object):
    pass

class connections(object):
    def __init__(args):
        self.args = args
        self.build()

    def build(self):
        if self.args.keystone:
            self.auth =  openstack(self.args)
        endpoints = self.auth.get_endpoints()

class Struct(object):
    def __init__(self, entries):
        self.__dict__.update(entries)

def parse_args(argv):
    def parse_cli():
        parser = argparse.ArgumentParser(description=__doc__)
        for var in user_inputs:
            parser.add_argument(var, action='store')
        return parser.parse_args(argv)
    def build_args(cli_args):
        args = dict()
        for var in user_inputs:
            args[var] = cli_args.getattr(var, None) or os.getenv(var) or defaults.get(var, None)
        return Struct(args)
    return Struct(build_args(parse_cli()))

def main():
     pargs = parse_args(sys.argv[1:])
     conn = connections(pargs).get_connections()

if __name__ == '__main__':
    main()
