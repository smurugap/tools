import time
import pytun
import subprocess

def enable_tapinterface(tap_intf, dummy_dict):
    try:
        dummy_dict[tap_intf] = pytun.TapTunnel(pattern=tap_intf)
    except IOError:
        pass

def get_tapinterfaces():
    output = subprocess.Popen("ip link | grep tap | awk '{print $2}'", stdout=subprocess.PIPE, shell=True, executable="/bin/bash").stdout.read().strip()
    tap_list = []
    for line in output.split('\n'):
        if line:
            tap_list.append(line.strip(':'))
    return set(tap_list)

def main():
    dummy_dict = dict()
    active_tap_list = set(list())
    while True:
        tap_list = get_tapinterfaces()
        count = 1
        for tap_intf in list(tap_list-active_tap_list):
            enable_tapinterface(tap_intf, dummy_dict)
            if not count % 100:
                time.sleep(5)
            count += 1
        active_tap_list = tap_list
        time.sleep(10)

if __name__ == '__main__':
    main()
