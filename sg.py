from vnc_api.vnc_api import *
import uuid
import argparse

def parse_cli(args):
    '''Define and Parse arguments for the script'''
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sg_name',
                        action='store',
                        required=True,
                        help='SG Name')
    parser.add_argument('--vmis',
                        action='store',
                        default=[],
                        nargs='+',
                        help='Space separated list of vmi ids')
    pargs = parser.parse_args(args)
    return pargs

class SG(object):
    def __init__(self, sg_name, vmis=None):
        self.vnc = VncApi(username='admin',
                          password='contrail123',
                          tenant_name='admin')
        self.obj = self.create_sg(sg_name)
        for vmi in vmis or []:
            self.associate_vmi(vmi)

    def create_sg(self, sg_name):
        ''' Create Security group using VNC api '''
        fq_name = ['default-domain', 'admin', sg_name]
        def _get_rule(prefix, ethertype):
            dst_addr = AddressType(subnet=SubnetType(prefix, 0))
            src_addr = AddressType(security_group='local')
            rule = PolicyRuleType(rule_uuid=str(uuid.uuid4()), direction='>',
                                  protocol='any', src_addresses=[src_addr],
                                  src_ports=[PortType(0, 65535)],
                                  dst_addresses=[dst_addr],
                                  dst_ports=[PortType(0, 65535)],
                                  ethertype=ethertype)
            return rule

        try:
            self.obj = self.vnc.security_group_read(fq_name=fq_name)
            self.uuid = self.obj.uuid
            return self.obj
        except NoIdError:
            rules = [_get_rule('0.0.0.0', 'IPv4'), _get_rule('::', 'IPv6')]
            sg_obj = SecurityGroup(name=sg_name, parent_type='project', fq_name=fq_name,
                                   security_group_entries=PolicyEntriesType(rules))
            self.uuid = self.vnc.security_group_create(sg_obj)
            print sg_obj.uuid
            return sg_obj

    def associate_vmi(self, vmi_id):
        vmi_obj = self.vnc.virtual_machine_interface_read(id=vmi_id)
        vmi_obj.add_security_group(self.obj)
        self.vnc.virtual_machine_interface_update(vmi_obj)

def main():
    args = parse_cli(sys.argv[1:])
    tmpfile = SG(args.sg_name, args.vmis)

if __name__ == '__main__':
    main()

