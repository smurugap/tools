import sys
import ast
import argparse
from fabric.api import *
from tempfile import NamedTemporaryFile

fakeTestDriver = '''
"""
A fake (in-memory) hypervisor+api.

Allows nova testing w/o a hypervisor.  This module also documents the
semantics of real hypervisor connections.

"""

from nova.openstack.common.gettextutils import _

try:
    from oslo.config import cfg
except:
    from oslo_config import cfg
CONF = cfg.CONF
from nova.virt import fake
from nova.virt import virtapi
try:
    from nova.openstack.common import importutils
except:
    from oslo_utils import importutils
try:
    from nova_contrail_vif.contrailvif import VRouterVIFDriver as VIFDriver
except:
    from nova.virt.libvirt.vif import LibvirtGenericVIFDriver as VIFDriver

_FAKE_NODES = None

class FakeTestDriver(fake.FakeDriver):
    def __init__(self, virtapi, read_only=False):
        super(FakeTestDriver, self).__init__(virtapi)
        self.vif_driver = VIFDriver()

    def plug_vifs(self, instance, network_info):
        """Plug VIFs into networks."""
        for vif in network_info:
            self.vif_driver.plug(instance, vif)

    def unplug_vifs(self, instance, network_info):
        """Unplug VIFs from networks."""
        for vif in network_info:
            self.vif_driver.unplug(instance, vif)

    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, network_info=None, block_device_info=None):
        super(FakeTestDriver, self).spawn(context, instance, image_meta,
                                    injected_files, admin_password,
                                    network_info=None, block_device_info=None)
        self.plug_vifs(instance, network_info)

    def destroy(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True):
        super(FakeTestDriver, self).destroy(context, instance, network_info,
                                            block_device_info=None,
                                            destroy_disks=True)
        self.unplug_vifs(instance, network_info)
'''

def get_dist():
    linux_distro = "python -c 'from platform import linux_distribution; print linux_distribution()'"
    (dist, version, extra) = ast.literal_eval(sudo(linux_distro))
    return dist

def get_python_path():
    dist = get_dist()
    if dist in ['centos', 'fedora', 'redhat']:
        pythonpath = '/usr/lib/python2.6/site-packages'
    else:
        pythonpath = '/usr/lib/python2.7/dist-packages'
    return pythonpath

def fixup_nova_compute(faketestdriver, reset=False):
    pythonpath = get_python_path()
    if not reset:
        put(faketestdriver, "%s/nova/virt/fakeTest.py"%(pythonpath), use_sudo=True)
        compute_driver = "fakeTest.FakeTestDriver"
        connection_type = "fakeTest"
    else:
        compute_driver = "libvirt.LibvirtDriver"
        connection_type = "libvirt"
    sudo("sed -i -e 's/connection_type.*$/connection_type=%s/g' \
                              /etc/nova/nova.conf"%(connection_type))
    sudo("sed -i -e 's/connection_type.*$/connection_type=%s/g' \
                              /etc/nova/nova-compute.conf"%(connection_type))
    sudo("sed -i -e 's/compute_driver.*$/compute_driver=%s/g'\
                              /etc/nova/nova.conf"%(compute_driver))
    sudo("sed -i -e 's/compute_driver.*$/compute_driver=%s/g'\
                              /etc/nova/nova-compute.conf"%(compute_driver))
    sudo("service nova-compute restart", pty=False)

def fixup_nova_scheduler():
    replace_string="scheduler_default_filters=RetryFilter,"+\
                   "AvailabilityZoneFilter,ComputeFilter,"+\
                   "ComputeCapabilitiesFilter,ImagePropertiesFilter"
    sudo("sed -i -e '/compute_driver.*$/a %s' \
                    /etc/nova/nova.conf" %replace_string) #add this in openstack
    sudo("service nova-scheduler restart", pty=False)

def fixup_nova(args, faketestdriver):
    for compute in args.computes:
        with settings(host_string='%s@%s'%(args.username, compute),
                      password=args.password, warn_only=True):
            fixup_nova_compute(faketestdriver, args.reset)
    for openstack in args.controllers:
        with settings(host_string='%s@%s'%(args.username, openstack), 
                      password=args.password, warn_only=True):
            fixup_nova_scheduler()

def create_faketest_driver():
    tempfile = NamedTemporaryFile(delete=False)
    with open(tempfile.name, 'w') as fd:
        fd.write('\n%s\n' %fakeTestDriver)
        fd.flush()
    return tempfile.name

def parse_cli(args):
    '''Define and Parser arguments for the script'''
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--username',
                        action='store',
                        required=True,
                        help='Login ID')
    parser.add_argument('--password',
                        action='store',
                        required=True,
                        help='Password')
    parser.add_argument('--controllers',
                        action='store',
                        default=[],
                        nargs='+',
                        help='Space separated list of openstack controllers')
    parser.add_argument('--computes',
                        action='store',
                        default=[],
                        nargs='+',
                        help='Space separated list of compute nodes')
    parser.add_argument('--reset',
                        action='store_true',
                        help='Reset to Libvirt')
    pargs = parser.parse_args(args)
    return pargs

def main():
    args = parse_cli(sys.argv[1:])
    tmpfile = create_faketest_driver()
    fixup_nova(args, tmpfile)

if __name__ == '__main__':
    main()

