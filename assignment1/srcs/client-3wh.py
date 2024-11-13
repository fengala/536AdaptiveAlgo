#!/usr/bin/env python

############################################################################
##
##     This file is part of Purdue CS 536.
##
##     Purdue CS 536 is free software: you can redistribute it and/or modify
##     it under the terms of the GNU General Public License as published by
##     the Free Software Foundation, either version 3 of the License, or
##     (at your option) any later version.
##
##     Purdue CS 536 is distributed in the hope that it will be useful,
##     but WITHOUT ANY WARRANTY; without even the implied warranty of
##     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##     GNU General Public License for more details.
##
##     You should have received a copy of the GNU General Public License
##     along with Purdue CS 536. If not, see <https://www.gnu.org/licenses/>.
##
#############################################################################

from scapy.all import *
import threading

SEND_PACKET_SIZE = 1000  # should be less than max packet size of 1500 bytes

# A client class for implementing TCP's three-way-handshake connection establishment and closing protocol,
# along with data transmission.


class Client3WH:

    def __init__(self, dip, dport):
        """Initializing variables"""
        self.dip = dip
        self.dport = dport
        # selecting a source port at random
        self.sport = random.randrange(0, 2**16)

        self.next_seq = 0                       # TCP's next sequence number
        self.next_ack = 0                       # TCP's next acknowledgement number

        self.ip = IP(dst=self.dip)              # IP header

        self.connected = False
        self.timeout = 3

    def _start_sniffer(self):
        t = threading.Thread(target=self._sniffer)
        t.start()

    def _filter(self, pkt):
        if (IP in pkt) and (TCP in pkt):  # capture only IP and TCP packets
            return True
        return False

    def _sniffer(self):
        while self.connected:
            sniff(prn=lambda x: self._handle_packet(
                x), lfilter=lambda x: self._filter(x), count=1, timeout=self.timeout)

    def _handle_packet(self, pkt):
        """TODO(1): Handle incoming packets from the server and acknowledge them accordingly. Here are some pointers on
           what you need to do:
           1. If the incoming packet has data (or payload), send an acknowledgement (TCP) packet with correct 
              `sequence` and `acknowledgement` numbers.
           2. If the incoming packet is a FIN (or FINACK) packet, send an appropriate acknowledgement or FINACK packet
              to the server with correct `sequence` and `acknowledgement` numbers.
        """

        ### BEGIN: ADD YOUR CODE HERE ... ###
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        

        ### END: ADD YOUR CODE HERE ... #####

    def connect(self):
        """TODO(2): Implement TCP's three-way-handshake protocol for establishing a connection. Here are some
           pointers on what you need to do:
           1. Handle SYN -> SYNACK -> ACK packets.
           2. Make sure to update the `sequence` and `acknowledgement` numbers correctly, along with the 
              TCP `flags`.
        """

        ### BEGIN: ADD YOUR CODE HERE ... ###
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        

        ### END: ADD YOUR CODE HERE ... #####

        self.connected = True
        self._start_sniffer()
        print('Connection Established')

    def close(self):
        """TODO(3): Implement TCP's three-way-handshake protocol for closing a connection. Here are some
           pointers on what you need to do:
           1. Handle FIN -> FINACK -> ACK packets.
           2. Make sure to update the `sequence` and `acknowledgement` numbers correctly, along with the 
              TCP `flags`.
        """

        ### BEGIN: ADD YOUR CODE HERE ... ###
        
        
        
        
        
        
        
        
        
        
        

        ### END: ADD YOUR CODE HERE ... #####

        self.connected = False
        print('Connection Closed')

    def send(self, payload):
        """TODO(4): Create and send TCP's data packets for sharing the given message (or file):
           1. Make sure to update the `sequence` and `acknowledgement` numbers correctly, along with the 
              TCP `flags`.
        """

        ### BEGIN: ADD YOUR CODE HERE ... ###
        
        
        
        
        
        
        
        
        
        
        
        

        ### END: ADD YOUR CODE HERE ... #####


def main():
    """Parse command-line arguments and call client function """
    if len(sys.argv) != 3:
        sys.exit(
            "Usage: ./client-3wh.py [Server IP] [Server Port] < [message]")
    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])

    client = Client3WH(server_ip, server_port)
    client.connect()

    message = sys.stdin.read(SEND_PACKET_SIZE)
    while message:
        client.send(message)
        message = sys.stdin.read(SEND_PACKET_SIZE)

    client.close()


if __name__ == "__main__":
    main()

