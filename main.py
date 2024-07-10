from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, ICMPv6EchoReply, Raw
import struct
import textwrap
import time

PCAP_GLOBAL_HEADER_FMT = '@ I H H i I I I '

# Global Header Values
PCAP_MAGICAL_NUMBER = 2712847316
PCAP_MJ_VERN_NUMBER = 2
PCAP_MI_VERN_NUMBER = 4
PCAP_LOCAL_CORECTIN = 0
PCAP_ACCUR_TIMSTAMP = 0
PCAP_MAX_LENGTH_CAP = 65535
PCAP_DATA_LINK_TYPE = 1

class Pcap:
    def __init__(self, filename, link_type=PCAP_DATA_LINK_TYPE):
        self.pcap_file = open(filename, 'wb')
        self.pcap_file.write(struct.pack(PCAP_GLOBAL_HEADER_FMT, PCAP_MAGICAL_NUMBER, PCAP_MJ_VERN_NUMBER, PCAP_MI_VERN_NUMBER, PCAP_LOCAL_CORECTIN, PCAP_ACCUR_TIMSTAMP, PCAP_MAX_LENGTH_CAP, link_type))

    def write(self, data):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(data)
        self.pcap_file.write(struct.pack('@ I I I I', ts_sec, ts_usec, length, length))
        self.pcap_file.write(data)

    def close(self):
        self.pcap_file.close()

class HTTP:
    def __init__(self, raw_data):
        try:
            self.data = raw_data.decode('utf-8')
        except:
            self.data = raw_data

def process_packet(packet):
    pcap.write(bytes(packet))
    pcap.pcap_file.flush()

    if Ether in packet:
        eth = packet[Ether]
        print('\nEthernet Frame:')
        print(f'\t - Destination: {eth.dst}, Source: {eth.src}, Type: {eth.type}')

    if IP in packet:
        ip = packet[IP]
        print('\t - IPv4 Packet:')
        print(f'\t\t - Version: {ip.version}, Header Length: {ip.ihl * 4}, TTL: {ip.ttl}')
        print(f'\t\t - Protocol: {ip.proto}, Source: {ip.src}, Target: {ip.dst}')

        if ip.proto == 1:  # ICMP
            icmp = packet[ICMP]
            print('\t - ICMP Packet:')
            print(f'\t\t - Type: {icmp.type}, Code: {icmp.code}, Checksum: {icmp.chksum}')
            print('\t - Data:')
            if Raw in packet:
                print(format_multi_line('\t\t\t', packet[Raw].load))

        elif ip.proto == 6:  # TCP
            tcp = packet[TCP]
            print('\t - TCP Segment:')
            print(f'\t\t - Source Port: {tcp.sport}, Destination Port: {tcp.dport}')
            print(f'\t\t - Sequence: {tcp.seq}, Acknowledgement: {tcp.ack}')
            print(f'\t\t - Flags:')
            print(f'\t\t\t - URG: {tcp.flags & 0x20}, ACK: {tcp.flags & 0x10}, PSH: {tcp.flags & 0x08}, RST: {tcp.flags & 0x04}, SYN: {tcp.flags & 0x02}, FIN: {tcp.flags & 0x01}')

            if Raw in packet:
                if tcp.sport == 80 or tcp.dport == 80:
                    print('\t\t - HTTP Data:')
                    http = HTTP(packet[Raw].load)
                    http_info = str(http.data).split('\n')
                    for line in http_info:
                        print(f'\t\t\t - {line}')
                else:
                    print('\t\t - TCP Data:')
                    print(format_multi_line('\t\t\t', packet[Raw].load))

        elif ip.proto == 17:  # UDP
            udp = packet[UDP]
            print('\t - UDP Segment:')
            print(f'\t\t - Source Port: {udp.sport}, Destination Port: {udp.dport}, Length: {udp.len}')
            if Raw in packet:
                print('\t\t - UDP Data:')
                print(format_multi_line('\t\t\t', packet[Raw].load))
        else:
            if Raw in packet:
                print('\t - Data:')
                print(format_multi_line('\t\t', packet[Raw].load))

    elif IPv6 in packet:
        ipv6 = packet[IPv6]
        print('\t - IPv6 Packet:')
        print(f'\t\t - Version: {ipv6.version}, Traffic Class: {ipv6.tc}, Flow Label: {ipv6.fl}')
        print(f'\t\t - Payload Length: {ipv6.plen}, Next Header: {ipv6.nh}, Hop Limit: {ipv6.hlim}')
        print(f'\t\t - Source: {ipv6.src}, Destination: {ipv6.dst}')

        if ipv6.nh == 58:  # ICMPv6
            if ICMPv6EchoRequest in packet:
                icmpv6 = packet[ICMPv6EchoRequest]
                print('\t - ICMPv6 Echo Request:')
                print(f'\t\t - Identifier: {icmpv6.id}, Sequence Number: {icmpv6.seq}')
                print('\t - Data:')
                if Raw in packet:
                    print(format_multi_line('\t\t\t', packet[Raw].load))

            elif ICMPv6EchoReply in packet:
                icmpv6 = packet[ICMPv6EchoReply]
                print('\t - ICMPv6 Echo Reply:')
                print(f'\t\t - Identifier: {icmpv6.id}, Sequence Number: {icmpv6.seq}')
                print('\t - Data:')
                if Raw in packet:
                    print(format_multi_line('\t\t\t', packet[Raw].load))

        elif ipv6.nh == 6:  # TCP
            tcp = packet[TCP]
            print('\t - TCP Segment:')
            print(f'\t\t - Source Port: {tcp.sport}, Destination Port: {tcp.dport}')
            print(f'\t\t - Sequence: {tcp.seq}, Acknowledgement: {tcp.ack}')
            print(f'\t\t - Flags:')
            print(f'\t\t\t - URG: {tcp.flags & 0x20}, ACK: {tcp.flags & 0x10}, PSH: {tcp.flags & 0x08}, RST: {tcp.flags & 0x04}, SYN: {tcp.flags & 0x02}, FIN: {tcp.flags & 0x01}')

            if Raw in packet:
                if tcp.sport == 80 or tcp.dport == 80:
                    print('\t\t - HTTP Data:')
                    http = HTTP(packet[Raw].load)
                    http_info = str(http.data).split('\n')
                    for line in http_info:
                        print(f'\t\t\t - {line}')
                else:
                    print('\t\t - TCP Data:')
                    print(format_multi_line('\t\t\t', packet[Raw].load))

        elif ipv6.nh == 17:  # UDP
            udp = packet[UDP]
            print('\t - UDP Segment:')
            print(f'\t\t - Source Port: {udp.sport}, Destination Port: {udp.dport}, Length: {udp.len}')
            if Raw in packet:
                print('\t\t - UDP Data:')
                print(format_multi_line('\t\t\t', packet[Raw].load))
        else:
            if Raw in packet:
                print('\t - Data:')
                print(format_multi_line('\t\t', packet[Raw].load))

def format_multi_line(pre, string, size=80):
    size -= len(pre)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([pre + line for line in textwrap.wrap(string, size)])

if __name__ == "__main__":
    pcap = Pcap('Temp.pcap')
    try:
        sniff(prn=process_packet)
    except KeyboardInterrupt:
        print("\nInterrupted, closing file.")
    finally:
        pcap.close()
        print("File closed.")
