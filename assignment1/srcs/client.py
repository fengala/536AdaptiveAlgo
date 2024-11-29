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
import matplotlib.pyplot as plt
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

        self.next_seq = 0  # TCP's next sequence number
        self.next_ack = 0  # TCP's next acknowledgement number

        self.ip = IP(dst=self.dip)  # IP header

        self.connected = False
        self.timeout = 3

        # New stuff
        self.R = 0.4  # Our timeout that adapts
        self.a = 6.0
        self.c = 10.0
        self.b = (self.a - 1) / self.a
        self.d = (self.c - 1) / self.c
        self.Y = 0.05  # Retransmission limit
        self.e = 0.4  # Small constant

        self.T = 0.2  # Smoothed RTT
        self.V = 0.01  # Variance

        self.avg_t = 0

        self.timeouts = 0

        self.rg = [self.R]
        self.tg = [self.T]
        self.rttg = []
        self.x_axis = [0]

    def _start_sniffer(self):
        t = threading.Thread(target=self._sniffer)
        t.start()

    def _filter(self, pkt):
        if (IP in pkt) and (TCP in pkt):  # capture only IP and TCP packets
            return True
        return False

    def _sniffer(self):
        while self.connected:
            sniff(
                prn=lambda x: self._handle_packet(x),
                lfilter=lambda x: self._filter(x),
                count=1,
                timeout=self.timeout,
            )

    def _handle_packet(self, pkt):
        """TODO(1): Handle incoming packets from the server and acknowledge them accordingly. Here are some pointers on
        what you need to do:
        1. If the incoming packet has data (or payload), send an acknowledgement (TCP) packet with correct
           `sequence` and `acknowledgement` numbers.
        2. If the incoming packet is a FIN (or FINACK) packet, send an appropriate acknowledgement or FINACK packet
           to the server with correct `sequence` and `acknowledgement` numbers.
        """

        ### BEGIN: ADD YOUR CODE HERE ... ###

        if TCP in pkt:
            tcp_layer = pkt[TCP]
            ip_src = pkt[IP].src
            if ip_src == self.dip:  # Filter out outgoing packets
                # pkt.show()

                if tcp_layer.flags == "F":
                    self.next_ack = tcp_layer.seq + 1
                    finack_pkt = self.ip / TCP(
                        sport=self.sport,
                        dport=self.dport,
                        flags="FA",
                        seq=self.next_seq,
                        ack=self.next_ack,
                    )
                    send(ack_pkt)
                    self.next_seq += 1

                if tcp_layer.flags == "FA":
                    self.next_ack = tcp_layer.seq + 1
                    ack_pkt = self.ip / TCP(
                        sport=self.sport,
                        dport=self.dport,
                        flags="A",
                        seq=self.next_seq,
                        ack=self.next_ack,
                    )
                    send(ack_pkt)
                    self.next_seq += 1

        ### END: ADD YOUR CODE HERE ... #####

    def connect(self):
        """TODO(2): Implement TCP's three-way-handshake protocol for establishing a connection. Here are some
        pointers on what you need to do:
        1. Handle SYN -> SYNACK -> ACK packets.
        2. Make sure to update the `sequence` and `acknowledgement` numbers correctly, along with the
           TCP `flags`.
        """

        ### BEGIN: ADD YOUR CODE HERE ... ###

        syn_pkt = self.ip / TCP(
            sport=self.sport, dport=self.dport, flags="S", seq=self.next_seq
        )
        self.next_seq += 1
        send(syn_pkt)

        bpf_filter = "tcp and host {} and port {}".format(self.dip, self.dport)
        synack_pkt = sniff(filter=bpf_filter, count=1)[0]

        # while (synack_pkt[TCP].flags != 18):
        # synack_pkt = sniff(filter=bpf_filter, count=1)[0]
        self.next_ack = synack_pkt[TCP].seq + 1
        ack_pkt = self.ip / TCP(
            sport=self.sport,
            dport=self.dport,
            flags="A",
            seq=self.next_seq,
            ack=self.next_ack,
        )
        send(ack_pkt)

        ### END: ADD YOUR CODE HERE ... #####

        self.connected = True
        self._start_sniffer()
        print("Connection Established")

    def close(self):
        """TODO(3): Implement TCP's three-way-handshake protocol for closing a connection. Here are some
        pointers on what you need to do:
        1. Handle FIN -> FINACK -> ACK packets.
        2. Make sure to update the `sequence` and `acknowledgement` numbers correctly, along with the
           TCP `flags`.
        """

        ### BEGIN: ADD YOUR CODE HERE ... ###

        fin_pkt = self.ip / TCP(
            sport=self.sport,
            dport=self.dport,
            flags="FA",
            seq=self.next_seq,
            ack=self.next_ack,
        )
        send(fin_pkt)

        # Handling the FINACK from server is handled in handle_packet

        ### END: ADD YOUR CODE HERE ... #####

        self.connected = False
        print("Connection Closed")

    def send(self, payload):
        """TODO(4): Create and send TCP's data packets for sharing the given message (or file):
        1. Make sure to update the `sequence` and `acknowledgement` numbers correctly, along with the
           TCP `flags`.
        """

        ### BEGIN: ADD YOUR CODE HERE ... ###

        data_pkt = (
            self.ip
            / TCP(
                sport=self.sport,
                dport=self.dport,
                flags="PA",
                seq=self.next_seq,
                ack=self.next_ack,
            )
            / Raw(load=payload)
        )

        start_time = time.time()
        response = sr1(data_pkt, timeout=self.R)
        if response:
            t = time.time() - start_time  # Around 0.025
            # print(self.R)
            # print(t)
            self.avg_t += t
            self.V = self.d * self.V + ((t - self.T) ** 2) / self.c
            self.T = self.b * self.T + t / self.a
            self.R = self.T + self.e * ((self.V * (1 - self.Y) / self.Y) ** (1 / 2))

            self.rg.append(self.R)
            self.tg.append(self.T)
            self.rttg.append(t)
            self.x_axis.append(self.x_axis[-1] + 1)
            self.next_seq += len(payload)

        else:
            self.timeouts += 1
            self.avg_t += self.R

        ### END: ADD YOUR CODE HERE ... #####


def main():
    """Parse command-line arguments and call client function"""
    if len(sys.argv) != 3:
        sys.exit("Usage: ./client-3wh.py [Server IP] [Server Port] < [message]")
    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])

    client = Client3WH(server_ip, server_port)
    client.connect()

    message = sys.stdin.read(SEND_PACKET_SIZE)
    x = 100
    for i in range(1, x):
        client.send(message)
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
    plt.savefig("graph.png")

    client.close()


if __name__ == "__main__":
    main()
