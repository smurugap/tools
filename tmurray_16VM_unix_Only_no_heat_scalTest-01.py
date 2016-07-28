#!/usr/bin/python

import os
import sys
import time
import uuid
from pprint import pprint
from concurrent import futures
from keystoneclient.v2_0 import client as ks_client
from novaclient import client as nova_client
#from neutronclient.neutron import client as neutron_client
from vnc_api.vnc_api import *

DOMAIN='default-domain'
TENANT='scalTest-01'
#NEUTRON_ENDPOINT = "http://10.93.3.59:9696"
CONTRAIL_API_IP = "10.84.7.42"
CONTRAIL_API_PORT = "8082"
FLAVOR_ID = "3" # "m1.medium"
CIDR = "20.10.1.0/24"
IMAGE_ID = "ceb1f783-cca5-4db0-ab59-4558af2e8010" # "cirros-0.3.4-x86_64"
#EXTNET_ID = '7d1457c9-6637-4e37-a4ba-19551493022d' # ext-net
PUBLIC_VN = 'Public'
ADMIN_TENANT='admin'

def get_vnc_api_h():
    vnc_api_h = VncApi(api_server_host=CONTRAIL_API_IP,
                       api_server_port=CONTRAIL_API_PORT,
                       auth_token=ks_token)
    return vnc_api_h

def create_port(vnc_api_h, name, vn_obj):
    fq_name = [DOMAIN, TENANT, name]
    port_obj = VirtualMachineInterface(name, parent_type='project', fq_name=fq_name)
    port_id = port_obj.uuid = str(uuid.uuid4())
    port_obj.add_virtual_network(vn_obj)
    vnc_api_h.virtual_machine_interface_create(port_obj)

    iip_obj = InstanceIp(name='__'.join(fq_name))
    iip_obj.uuid = iip_id = str(uuid.uuid4())
    iip_obj.add_virtual_network(vn_obj)
    iip_obj.add_virtual_machine_interface(port_obj)
    vnc_api_h.instance_ip_create(iip_obj)
    return port_obj

def create_and_assoc_fip(vnc_api_h, name, port_obj):
    fq_name = [DOMAIN, ADMIN_TENANT, PUBLIC_VN, "floating-ip-pool", name]
    fip_obj = FloatingIp(name=fip_id, parent_type='floating-ip-pool', fq_name=fq_name)
    fip_id = fip_obj.uuid = str(uuid.uuid4())
    fip_obj.add_virtual_machine_interface(port_obj)
#    proj_obj = vnc_api_h.project_read(fq_name=[DOMAIN, TENANT])
#    fip_obj.add_project(proj_obj)
    vnc_api_h.floating_ip_create(fip_obj)
    return fip_id

def create_network(vnc_api_h, name):
    cidr, mask = CIDR.split('/')
    fq_name = [DOMAIN, TENANT, name]
    vn_obj = VirtualNetwork(vn_name, parent_type='project', fq_name=fq_name)
    vn_obj.add_network_ipam(NetworkIpam(),
                            VnSubnetsType([IpamSubnetType(
                            subnet=SubnetType(cidr, mask))]))
    vnc_api_h.virtual_network_create(vn_obj)

def create_tenant_port(name):
    print "create_tenant_port %s starting\n" % (name)
    vnc_api_h = get_vnc_api_h()

    vn_fq_name = [DOMAIN, TENANT, TENANT + '-net']
    vn_obj = vnc_api_h.virtual_network_read(fq_name=vn_fq_name)
    port_obj = create_port(vnc_api_h, name + "_tenant_port", vn_obj)
    fip_id = create_and_assoc_fip(vnc_api_h, name + "_fip", port_obj)
    return port_obj.uuid

def create_private_port(name):
    print "create_private_port %s starting\n" % (name)
    vnc_api_h = get_vnc_api_h()

    vn_obj = create_network(vnc_api_h, name + "_private_net")
    port_obj = create_port(vnc_api_h, name + "_port", vn_obj)
    return port_obj.uuid

def create_topology(name):
    print "create_topology %s starting\n" % (name)

    executor = futures.ThreadPoolExecutor(max_workers=2)
    tenant_port_job = executor.submit(create_tenant_port, name)
    private_port_job = executor.submit(create_private_port, name)

    nova = nova_client.Client('2', auth_token_=ks_token, username=ks_name, api_key=ks_pass, project_id=ks_tenant, auth_url=ks_auth)

    tenant_port_id = tenant_port_job.result()
    private_port_id = private_port_job.result()
    nics = [{'port-id': tenant_port_id}, {'port-id': private_port_id}]
    vm_name = name + "_unix"

    response = nova.servers.create(name=vm_name, flavor=FLAVOR_ID, image=IMAGE_ID, nics=nics)

    '''
    # Poll at 5 second intervals, until the status is no longer 'BUILD'
    status = response.status
    while status == 'BUILD':
        time.sleep(5)
        # Retrieve the instance again so the status field updates
        response = nova.servers.get(response.id)
        status = response.status

    print "VM created: %s: %s" % (response, status)
    '''

    print "create_topology %s complete\n" % (name)

ks_name = os.environ['OS_USERNAME']
print "ks_name = '%s'" % ks_name
ks_pass = os.environ['OS_PASSWORD']
print "ks_pass = '%s'" % ks_pass
ks_tenant = TENANT#os.environ['OS_TENANT_NAME']
print "ks_tenant = '%s'" % ks_tenant
ks_auth = os.environ['OS_AUTH_URL']
print "ks_auth = '%s'" % ks_auth

keystone = ks_client.Client(username=ks_name, password=ks_pass, tenant_name=ks_tenant, auth_url=ks_auth)
ks_token = keystone.auth_token


# Fire off concurrent topology creates

jobs = []
with futures.ThreadPoolExecutor(max_workers=16) as executor:
    for i in range(1,17):
        inst = "%s%s" % ("r",i)
        jobs.append(executor.submit(create_topology,inst))
for future in futures.as_completed(jobs):
   print "Jobs completed %s" % (future.result())
