import os
import re
import tempfile
import argparse
import logging
import time
from fabric.api import local, run, sudo
from fabric.operations import get, put
from fabric.context_managers import lcd, settings

def main(client_ips, password, server_ip, n_clients, datasize):
    datasize_list=[1, 512, 1400]
    n_clients_list=[1, 2, 4, 8]
    if datasize:
        datasize_list=[datasize]
    if n_clients:
        n_clients_list=[n_clients]

    filename = './'+time.strftime("%Y%m%d-%H%M%S")+".log"
    logging.basicConfig(filename=filename, level=logging.WARN)

    for client_ip in client_ips:
        with settings(host_string= 'root@%s' %(client_ip), password= password):
            tune_host()
            put_netperf_files()

    for datasize in datasize_list:
        for n_clients in n_clients_list:
            interval = 60
            max_iterations = 5
            total_trans_per_second = 0
            tmpdir = '/tmp/'+time.strftime("%Y%m%d-%H%M%S")
            for client_ip in client_ips:
                with settings(host_string = 'root@%s' %(client_ip), password = password):
                    sudo('mkdir -p %s' %tmpdir)
                    run_netperf_client(server_ip, n_clients, datasize, interval, max_iterations, tmpdir)
            logging.debug("Sleep for %s seconds until all the iterations are done"%(interval*3))
            time.sleep(interval*3 + 10)
            for client_ip in client_ips:
                retry=0
                with settings(host_string = 'root@%s' %(client_ip), password = password):
                    while retry < 3:
                        try:
                            total_trans_per_second += get_result(n_clients, datasize, tmpdir)
                            break
                        except:
                            retry += 1
                            time.sleep(interval)
            logging.warn("For %s byte datasize and %d clients the average transactions per second is %d"%(datasize, n_clients, (total_trans_per_second/len(client_ips))))

def run_netperf_client(server_ip, n_clients, datasize, interval, iterations, tmpdir):
  try:
    logging.debug("Running netperf client for %s datasize with %d clients"%(datasize, n_clients))
    for i in range (n_clients):
        outputfile = '%s/%d.result'%(tmpdir, i)
        binary = './netperf'
        args = ' -H %s -t TCP_RR -i 5,3 -l %s -P 0 -- -r %s -k "MIN_LATENCY, MAX_LATENCY, MEAN_LATENCY, RT_LATENCY, P50_LATENCY, P90_LATENCY, P99_LATENCY, STDDEV_LATENCY, TRANSACTION_RATE"'%(server_ip, interval, datasize)
        #if iterations > 3:
        #    args = ' -i %s %s' %(iterations, args)
        cmdline = binary+args+" >> %s &"%outputfile
        if not sudo(cmdline, pty=False).succeeded:
            logging.error("Unable to start netperf client")
            import pdb; pdb.set_trace()
  except:
    import pdb; pdb.set_trace()

def get_result(n_clients, datasize, tmpdir):
    trans_per_second = 0
    min_lt = 200000
    max_lt = 0
    mean_lt = 0
    rt_lt = 0
    std_lt = 0
    for i in range(n_clients):
        outputfile = '%s/%d.result'%(tmpdir, i)
        #with open(outputfile, 'r') as fd:
        #    output = fd.read()
        with settings(warn_only = True):
            output = sudo('cat %s' %outputfile)
            #pattern = '^\d+\s+\d+\s+\d+\s+\d+\s+[\d\.]+\s+([\d\.]+)'
            pattern = 'TRANSACTION_RATE=([\d\.]+)'
            match = re.search(pattern, output, re.M | re.I)
            trans_per_second += int(float(match.group(1)))
            logging.warn("For client %d, output is %s" %(i, output))
            logging.debug("For client %d, transactions per second is %s" %(i, match.group(1)))

            pattern_minlt = 'MIN_LATENCY=([\d\.]+)'
            pattern_maxlt = 'MAX_LATENCY=([\d\.]+)'
            pattern_meanlt = 'MEAN_LATENCY=([\d\.]+)'
            pattern_rtlt = 'RT_LATENCY=([\d\.]+)'
            pattern_stdlt = 'STDDEV_LATENCY=([\d\.]+)'

            match = re.search(pattern_minlt, output, re.M | re.I)
            if int(float(match.group(1))) < min_lt:
                min_lt = int(float(match.group(1)))
            match = re.search(pattern_maxlt, output, re.M | re.I)
            if int(float(match.group(1))) > max_lt:
                max_lt = int(float(match.group(1)))
            match = re.search(pattern_meanlt, output, re.M | re.I)
            mean_lt += int(float(match.group(1)))
            match = re.search(pattern_rtlt, output, re.M | re.I)
            rt_lt += int(float(match.group(1)))
            match = re.search(pattern_stdlt, output, re.M | re.I)
            std_lt += int(float(match.group(1)))
    logging.warn("Min LAT: %s, Max LAT: %s, RT_LAT: %s, MEAN_LAT: %s, STD_LAT: %s" %(min_lt, max_lt, rt_lt/n_clients, mean_lt/n_clients, std_lt/n_clients))
    return trans_per_second/n_clients

def put_netperf_files():
    logging.debug("copying netperf files")
    with settings(warn_only = True):
        if not put("~/net*", "~/").succeeded:
            logging.error("Unable to copy files to remote host")
        sudo("killall -e netserver")
    sudo("chmod 777 ./netperf")

def tune_host():
    logging.debug("setting cpu mode to performance")
    cmdline ='for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor ; do echo performance > $f; cat $f; done'
    with settings(warn_only = True):
        if not sudo(cmdline).succeeded:
            logging.error("Unable to tune the host")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--server_ip', required=True)
    parser.add_argument('--client_ips', default='127.0.0.1', nargs='+')
    parser.add_argument('--client_passwd', default='c0ntrail123')
    parser.add_argument('--n_clients', default='0')
    parser.add_argument('--data_size', default='0')
    args = parser.parse_args()
    #Client = Host(args.client_ips, args.client_passwd, int(args.n_clients))
    main(client_ips=args.client_ips, password=args.client_passwd, n_clients=int(args.n_clients), server_ip=args.server_ip, datasize=int(args.data_size))
    #main(server_ip=args.server_ip, n_clients=int(args.n_clients), datasize=int(args.data_size))
