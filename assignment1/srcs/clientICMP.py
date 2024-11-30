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
import matplotlib as mpl

mpl.use("Agg")

from scapy.all import *
from scapy.all import IP, ICMP
import matplotlib.pyplot as plt
import threading

SEND_PACKET_SIZE = 1000  # should be less than max packet size of 1500 bytes

# A client class for implementing TCP's three-way-handshake connection establishment and closing protocol,
# along with data transmission.


class Client:

    def __init__(self, dip):
        """Initializing variables"""
        self.dip = dip

        self.ip = IP(dst=self.dip)  # IP header

        self.connected = False
        self.timeout = 3

        # New stuff
        self.R = 0.13  # Our timeout that adapts
        self.a = 6.0
        self.c = 10.0
        self.b = (self.a - 1) / self.a
        self.d = (self.c - 1) / self.c
        self.Y = 0.05  # Retransmission limit
        self.e = 0.4  # Small constant

        self.T = 0.12  # Smoothed RTT
        self.V = 0.00001  # Variance

        self.avg_t = 0

        self.timeouts = 0
        self.losses = 0

        self.rg = [self.R]
        self.tg = [self.T]
        self.rttg = []
        self.x_axis = [0]

    def _start_sniffer(self):
        t = threading.Thread(target=self._sniffer)
        t.start()

    def _filter(self, pkt):
        if (IP in pkt and ICMP in pkt):  # capture only IP and TCP packets
            return True
        return False

    def send(self, payload, seq):
        """TODO(4): Create and send TCP's data packets for sharing the given message (or file):
        1. Make sure to update the `sequence` and `acknowledgement` numbers correctly, along with the
           TCP `flags`.
        """

        ### BEGIN: ADD YOUR CODE HERE ... ###

        data_pkt = IP(dst=self.dip, ttl=1) / ICMP(type=8, seq=seq) / Raw(payload)

        pkts, _ = sr(data_pkt, timeout=1, verbose=None)
        t = self.T
        did_timeout = False
        if pkts:
            response = pkts[0]
            sent = response[0].sent_time
            rec = response[1].time
            t = rec - sent
            print(t)
        else:
            self.losses += 1
            did_timeout = True
        
        self.avg_t += t
        if t >= self.R or did_timeout:
            self.timeouts += 1
        
        self.V = self.d * self.V + ((t - self.T) ** 2) / self.c
        self.T = self.b * self.T + t / self.a
        self.R = self.T + self.e * (math.sqrt(self.V * (1 - self.Y) / self.Y))

        self.rg.append(self.R)
        self.tg.append(self.T)
        self.rttg.append(t)
        self.x_axis.append(self.x_axis[-1] + 1)


        ### END: ADD YOUR CODE HERE ... #####


def main():
    """Parse command-line arguments and call client function"""
    if len(sys.argv) != 2:
        sys.exit("Usage: ./client-3wh.py [Server IP]")
    server_ip = sys.argv[1]

    client = Client(server_ip)

    message = "X" * 56
    x = 100
    for i in range(0, x):
        client.send(message, i)
    print(client.avg_t / x)

    plt.plot(client.x_axis, client.rg, label="R value")
    plt.plot(client.x_axis, client.tg, label="T value")
    plt.plot(client.x_axis[1:], client.rttg, label="rtt")
    plt.xlabel("Packet number")
    plt.ylabel("Time in s")
    plt.title(
        "Change in R and T, Y = {}, e = {}, a = {}, c = {}".format(
            client.Y, client.e, client.a, client.c
        )
    )
    plt.legend()
    plt.show()
    plt.savefig("graphICMP.png")
    
    print("drops: {} / timeouts: {}".format(client.losses, client.timeouts))


if __name__ == "__main__":
    main()