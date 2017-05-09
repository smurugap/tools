from vnc_api.vnc_api import *
import argparse

def parse_cli(args):
    '''Define and Parse arguments for the script'''
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mtu',
                        action='store',
                        required=True,
                        help='default mtu of the interfaces')
    parser.add_argument('--username',
                        action='store',
                        default='admin',
                        help='Tenant user name [admin]')
    parser.add_argument('--password',
                        action='store',
                        default='contrail123',
                        help="Tenant user's password [contrail123]")
    parser.add_argument('--tenant_name',
                        action='store',
                        default='admin',
                        help='Tenant name [admin]')
    pargs = parser.parse_args(args)
    return pargs

class SetMtu(object):
    def __init__(self, username, password, tenant_name, mtu):
        self.vnc = VncApi(username=username,
                          password=password,
                          tenant_name=tenant_name)
        ipam_fqname = ['default-domain', 'default-project', 'default-network-ipam']
        self.set_mtu(ipam_fqname, mtu)

    def set_mtu(self, fqname, mtu):
        ''' Create Security group using VNC api '''
        self.obj = self.vnc.network_ipam_read(fq_name=fqname)
        ipam_type = IpamType(ipam_method='dhcp', dhcp_option_list=DhcpOptionsListType(
                             dhcp_option=[DhcpOptionType(dhcp_option_name='26',
                             dhcp_option_value=mtu, dhcp_option_value_bytes='2')]))
        self.obj.set_network_ipam_mgmt(ipam_type)
        self.vnc.network_ipam_update(self.obj)

def main():
    args = parse_cli(sys.argv[1:])
    SetMtu(args.username, args.password, args.tenant_name, args.mtu)

if __name__ == '__main__':
    main()
