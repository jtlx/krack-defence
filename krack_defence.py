from scapy.all import *
import os, time, sys, signal
import pprint
from tabulate import tabulate

interface='wlan0mon'
ALERT_THRESHOLD = 4
logo = """
  _               _          _      __
 | |___ _ __ _ __| |_____ __| |___ / _|___ _ _  __ ___
 | / / '_/ _` / _| / /___/ _` / -_)  _/ -_) ' \/ _/ -_)
 |_\_\_| \__,_\__|_\_\   \__,_\___|_| \___|_||_\__\___|

 Written by: Chee Yi Hsien Shaun, Chew Hong Kai, Seow Wei Jie,
             Tan Wei, and Tang Lang Xing Joseph

"""

# TODO:
# 1. Disassociate the attacker by forging disassoc. or deauth packets

def clear():
    os.system('clear')


def get_largest_difference(lst):
    highest = 0
    lowest = 99
    for elem in lst:
        lowest = min(lowest, elem)
        highest = max(highest, elem)
    return highest - lowest


def pkt_handler(pkt):
    if pkt.haslayer(Dot11Beacon):
        addr = pkt.getlayer(Dot11).addr2
        ssid = pkt.getlayer(Dot11Elt).info

        # Handle a new MAC address
        if addr not in addr_to_channels:
            addr_to_channels[addr] = []
            addr_to_ssid[addr] = ssid
            addr_to_pkt_count[addr] = 0

        addr_to_pkt_count[addr] += 1
        # Handle a new channel for this MAC address
        if current_channel not in addr_to_channels[addr]:
            addr_to_channels[addr].append(current_channel)
            print "New: %s" % (ssid + " ch:" + str(current_channel))
            redraw_output()


def redraw_output():
    clear()
    # get things into a table
    # Columns: name, ssid, num_pkts, channels, alert
    table = []
    for addr in addr_to_channels:
        ssid = addr_to_ssid[addr]
        num_pkts = addr_to_pkt_count[addr]
        channels = ",".join(str(x) for x in addr_to_channels[addr])
        curr_largest_difference = get_largest_difference(addr_to_channels[addr])
        if curr_largest_difference > ALERT_THRESHOLD: status = "Possibly being cloned by Rogue AP!"
        else: status = "OK"
        table.append([ssid, addr, num_pkts, channels, status])
    print logo
    print " Scanning CH " + str(current_channel)
    print "\n\n"
    print tabulate(table, headers=["SSID", "MAC Address", "#Packets", "Channels", "Status"])


if __name__ == "__main__":

    # Handle interrupts
    def handle_sigint(a,b):
        print "\nReceived interrupt. Stopping."
        sys.exit(0)
    signal.signal(signal.SIGINT, handle_sigint)

    # Keep a mapping of MAC addresses to SSIDs
    addr_to_ssid = {}

    # Keep a count of pkt received
    addr_to_pkt_count = {}

    # Keep a list of seen channels for every MAC address we see
    addr_to_channels = {}

    # Continuously scan all channels
    current_channel = 1
    while True:
        redraw_output()
        # Set channel
        ret = os.system('iwconfig %s channel %s' % (interface, current_channel))

        # Sniff on channel for x seconds
        sniff(iface=interface, prn=pkt_handler, timeout=0.1)

        # Cycle through all the channels
        current_channel += 1
        if current_channel == 14: current_channel = 1

