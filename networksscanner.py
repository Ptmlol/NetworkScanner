#!/usr/bin/env python

import scapy.all as scapy
import optparse
#import argparse


def get_arguments():
    #parser = argparse.ArgumentParser()
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="ip", help="Target IP/IP range.")
    #parser.add_argument("-t", "--target", dest="ip", help="Target IP/IP range.")
    (option, argument) = parser.parse_args() # no arguments on argparser only option
    return option


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] #only first element, second is [1] # add unanswered_list

    client_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}#0- send 1- response
        client_list.append(client_dict)
    return client_list


def print_result(result_list):
    print("IP\t\t\tMAC Address\n-----------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])


scan_result = scan(get_arguments().ip)
print_result(scan_result)
