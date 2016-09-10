from vnc_api.vnc_api import *
import uuid
class Base(object):
    def __init__(self):
          self.project_name = 'admin'
          self.uuid = None
          self.vnc = VncApi(api_server_host='127.0.0.1', api_server_port=8082, username='admin', password='contrail123',
                            tenant_name=self.project_name, auth_host='127.0.0.1')
 
class Policy(Base):
    def _get_rule(self, direction, protocol, min_port, max_port, action, src_vn=None, dst_vn=None, src_cidr=None, dst_cidr=None):
        src_addr = AddressType(virtual_network=src_vn,
                               subnet=SubnetType(ip_prefix=src_cidr.split('/')[0],
                                                 ip_prefix_len=int(src_cidr.split('/')[1])) if src_cidr else None)
        dst_addr = AddressType(virtual_network=dst_vn,
                               subnet=SubnetType(ip_prefix=dst_cidr.split('/')[0],
                                                 ip_prefix_len=int(dst_cidr.split('/')[1])) if dst_cidr else None)
        action_list = ActionListType(apply_service=action) if isinstance(action, list) \
                      else ActionListType(simple_action='pass')
        return PolicyRuleType(rule_uuid=str(uuid.uuid4()),
                              direction=direction,
                              protocol=protocol, src_addresses=[src_addr],
                              dst_addresses=[dst_addr],
                              src_ports=[PortType(min_port, max_port)],
                              dst_ports=[PortType(min_port, max_port)],
                              action_list=action_list)
 
    def create(self, name, left_vn_id=None, right_vn_id=None):
        self.fq_name = ['default-domain', self.project_name, name]
        try:
            self.obj = self.vnc.network_policy_read(fq_name=self.fq_name)
            self.uuid = self.obj.uuid
            return
        except:
            self.obj = NetworkPolicy(name, parent_type='project', fq_name=self.fq_name)
            self.uuid = self.vnc.network_policy_create(self.obj)
        left_vn_obj = self.vnc.virtual_network_read(id=left_vn_id)
        right_vn_obj = self.vnc.virtual_network_read(id=right_vn_id)
        left_vn_obj.add_network_policy(self.obj, VirtualNetworkPolicyType(sequence=SequenceType(major=0, minor=0)))
        right_vn_obj.add_network_policy(self.obj, VirtualNetworkPolicyType(sequence=SequenceType(major=0, minor=0)))
        self.vnc.virtual_network_update(left_vn_obj)
        self.vnc.virtual_network_update(right_vn_obj)
 
        return self.uuid
 
    def add_rule(self, uuid=None, protocol='any', min_port=-1, max_port=-1, si_fq_names=None, src_vn=None, dst_vn=None, src_cidr=None, dst_cidr=None):
        uuid = uuid or self.uuid
        obj = self.vnc.network_policy_read(id=uuid)
        entries = obj.get_network_policy_entries() or PolicyEntriesType(rules=[])
        entries.add_policy_rule(self._get_rule(direction='<>', protocol=protocol, min_port=min_port,
                                               max_port=max_port, action=si_fq_names,
                                               src_vn=src_vn, dst_vn=dst_vn, src_cidr=src_cidr, dst_cidr=dst_cidr))
        obj.set_network_policy_entries(entries)
        self.vnc.network_policy_update(obj)


policy=Policy()
policy.create("policy1")
policy.add_rule(policy.uuid, si_fq_names=["default-domain:admin:si-1"], src_vn="default-domain:admin:left-vn", dst_vn="default-domain:admin:right-vn", src_cidr="1.1.1.0/24")

