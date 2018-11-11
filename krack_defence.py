from scapy.all import *
import os, time, sys, signal
import pprint

interface='wlan0mon'

# TODO:
# 1. Prettify output
# 2. Disassociate the attacker by forging disassoc. or deauth packets

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

        # Handle a new channel for this MAC address
        if current_channel not in addr_to_channels[addr]:
            addr_to_channels[addr].append(current_channel)
            print "New: %s" % (ssid + " ch:" + str(current_channel))
            pprint.pprint(addr_to_channels)

            # Update and display the list of channels per MAC address
            for addr in addr_to_channels:
                curr_largest_difference = get_largest_difference(addr_to_channels[addr])
                sys.stdout.write(addr_to_ssid[addr] + " " + str(curr_largest_difference) + " channel(s) apart")
                if curr_largest_difference > 4:
                    sys.stdout.write("  <-- Possibly being cloned on another channel!")
                sys.stdout.write("\n")
                sys.stdout.flush()


if __name__ == "__main__":

    # Handle interrupts
    def handle_sigint(a,b):
        print "\nReceived interrupt. Stopping."
        sys.exit(0)
    signal.signal(signal.SIGINT, handle_sigint)

    # Keep a mapping of MAC addresses to SSIDs
    addr_to_ssid = {}

    # Keep a list of seen channels for every MAC address we see
    addr_to_channels = {}

    # Continuously scan all channels
    current_channel = 1
    while True:
        # Set channel
        ret = os.system('iwconfig %s channel %s' % (interface, current_channel))

        # Sniff on channel for x seconds
        sniff(iface=interface, prn=pkt_handler, timeout=0.1)

        # Cycle through all the channels
        current_channel += 1
        if current_channel == 14: current_channel = 1

