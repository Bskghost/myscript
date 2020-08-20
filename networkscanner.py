#!/usr/bin/python3.8
import scapy.all as scapy
from termcolor import colored
import argparse
import sys
from time import sleep

def get_input_from_user():
    parser = argparse.ArgumentParser(description="- 'We use Network scanner to discover all connected clinet on the same network'",
                                     usage='networkscanner.py -r [ip/range]')
    parser.add_argument('-t', '--target', dest='ip', help='Please specify IP / range.')
    args = parser.parse_args()
    return args


def scan(ip):
    arp_request = scapy.ARP()
    arp_request.pdst = ip
    broadcast = scapy.Ether()
    broadcast.dst = 'ff:ff:ff:ff:ff:ff'
    combination = broadcast / arp_request
    answered_list = scapy.srp(combination, timeout=1, verbose=0)[0]

    client_list = []
    for element in answered_list:
        client_dict = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def print_result(results_list):
    print('[{}] {}'.format(colored('*', 'blue', attrs=['bold']),
                           colored(' The network scanner is Running....', 'blue', attrs=["bold"])))
    sleep(1)
    print('-' * 52)
    print('[{}] IP\t\t\t\tMAC Address'.format(colored('+', 'blue')))
    print('-' * 52)
    for client in results_list:
        print(colored('[{}] {}\t\t\t{}'.format(colored('+', 'blue', attrs=['bold']), client['ip'], client['mac'])))

def main():
    try:
        args = get_input_from_user()
        ip_range = args.ip
        scan_result = scan(ip_range)
        print_result(scan_result)
    except:
        print('[{}] {}'.format(colored('+', 'red'), colored('There is an error Try to fix it of use help.', 'red')))
        sys.exit(1)

if __name__ == '__main__':
    main()


