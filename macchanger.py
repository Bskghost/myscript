#!/usr/bin/python3.8
import subprocess
import argparse
import re
from termcolor import colored
from time import sleep
import sys
import pyfiglet

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', dest='interface', help='Interface to change mac address.')
    parser.add_argument('-m', '--mac', dest='newmac', help='The new MAC address.')
    args = parser.parse_args()
    if not args.interface:
        print('[{}] {}'.format(colored('!', 'red', attrs=["bold"]),
                               colored(" Please specify an interface, use --help or -h for more info.", 'red', attrs=["bold"])))
        sys.exit(0)
    elif not args.newmac:
        print('[{}] {}'.format(colored('!', 'red', attrs=["bold"]),
                               colored(" Please specify a MAC address, use --help or -h for more info.", 'red', attrs=["bold"])))
        sys.exit(0)
    else:
        return args

def get_current_mac(interface):
    ifconfig_output = subprocess.check_output(['sudo', 'ifconfig', str(interface)])
    current_mac = re.search(r'(\w\w:){5}(\w\w)', str(ifconfig_output))
    if current_mac:
        return current_mac.group(0)
    else:
        print('[{}] {}'.format(colored('!', 'red', attrs=["bold"]), colored(" Could not read MAC address.", 'red')))
        sys.exit(0)

def change_mac_address(interface, newmac):
    ascii_banner = pyfiglet.figlet_format('ARP Poisoner')
    print(colored(ascii_banner.strip('\n'), 'cyan', attrs=['bold']))
    print('-' * 78)
    print('[{}] MAC changer is running....'.format(colored('+', 'cyan', attrs=['bold'])))
    print('-' * 78)
    sleep(0.2)
    print('[{}] Changing MAC address for {} to {}'.format(colored('+', 'cyan', attrs=["bold"]), interface, newmac))
    sleep(0.2)
    current_mac = get_current_mac(interface)
    print('[{}] Current MAC address after changing is {}'.format(colored('+', 'cyan'), str(current_mac)))

    subprocess.call(['sudo', 'ifconfig', str(interface), 'down'])
    subprocess.call(['sudo', 'ifconfig', str(interface), 'hw', 'ether', str(newmac)])
    sleep(0.2)
    print('[{}] Trying to change your MAC address to the new MAC {}'.format(colored('+', 'cyan', attrs=["bold"]), str(newmac)))

    subprocess.call(['sudo', 'ifconfig', str(interface), 'up'])

    get_new_mac = get_current_mac(interface)
    if get_new_mac != current_mac:
        print('[{}] The MAC address was successfully Changed to {}'.format(colored('+', 'cyan', attrs=["bold"]), str(get_new_mac)))
    else:
        print("[{}] {}".format(colored('!', 'red', attrs=["bold"]),
                               colored(" Ooops your MAC address didn't change To the new MAC {}".format(str(get_new_mac)),
                                       'red', attrs=["bold"])))
        sys.exit(0)

def main():
    arguments = get_arguments()
    interface = arguments.interface
    newmac = arguments.newmac
    change_mac_address(interface, newmac)

if __name__ == '__main__':
    main()
