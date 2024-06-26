# For CountTree class
from __future__ import annotations
from dataclasses import dataclass, field

# For live count screen
import curses, threading, time

# For arguments
import argparse, sys
from pathlib import Path

# Actually the important imports
from scapy.all import *
from scapy.layers import http
import socket

"""
----------
Exporting
----------
"""


def generate_title(title: str, sub: str = None, length: int = 40) -> str:
    return (
        "\n\n"
        + "-" * length
        + f"\n{title:^{length}}\n"
        + (f"{sub:^{length}}\n" if sub else "")
        + "-" * length
        + "\n"
    )


def dict_to_file(
    dic: dict, depth: int = 0, title: str = None, sub: str = None, smallest: int = 0
):
    global file
    if depth == 0 and title:
        file.write(generate_title(title, sub))
    for key, value in sorted(dic.items()):
        if isinstance(value, dict):
            file.write("    " * depth + f"{key:6}\n")
            dict_to_file(value, depth=depth + 1, smallest=smallest)
        else:
            if isinstance(value, int) and value < smallest:
                continue
            file.write("    " * (depth + 1) + f"{key:6}    {value}\n")


def check_ICMP(icmp_info: dict):
    global file
    file.write(generate_title("ICMP Pings"))
    for src, dest_info in sorted(icmp_info.items()):
        for dst, requests in sorted(dest_info.items()):
            echo_requests = sum(
                request_count
                for request_type, request_count in requests.items()
                if request_type.startswith("echo-request")
            )
            if "dest-unreach:network-unreachable" in requests.keys():
                file.write(f"{src} sent network-unreachable to {dst} - possible router")
            if echo_requests == 0:
                continue
            if dst in icmp_info.keys() and src in icmp_info[dst].keys():
                echo_replies = sum(
                    reply_count
                    for reply_type, reply_count in icmp_info[dst][src].items()
                    if reply_type.startswith("echo-reply")
                )
                if echo_replies / echo_requests >= 0.75:
                    file.write(f"{src} and {dst} pinging OK\n")
                else:
                    file.write(
                        f"{src} and {dst} pinging {echo_replies/echo_requests}\n"
                    )
            else:
                file.write(f"No ICMP reply between {src} and {dst}\n")

def export_ports(port_info: dict):
    global file
    file.write(generate_title("Ports", sub="Might show services - probably inaccurate"))
    for ip, port_breakdown in sorted(port_info.items()):
        if len(port_breakdown.keys()) >= 15:
            continue
        file.write(ip+"\n")
        for port_number, count in port_breakdown.items():
            try:
                possible_service = socket.getservbyport(port_number)
            except:
                possible_service = ""
            file.write("    " + f"{port_number:6} - {possible_service:12}    {count}\n")

def output_mac_to_ip(mac_to_ip: dict[str, set]):
    global file
    file.write(generate_title("MAC to multiple IP addresses", sub="Can show potential routers"))
    for mac_address, ip_addresses in mac_to_ip.items():
        if len(ip_addresses) > 1:
            file.write(f"{mac_address} has {len(ip_addresses)} IPs:\n    {sorted(ip_addresses)}\n")

"""
----------
Packet Stuff
----------
"""


def get_packet_layers(packet):
    yield packet.name
    while packet.payload:
        packet = packet.payload
        if packet.payload.name == packet.name:
            continue
        if packet.name != "Padding" and packet.name != "Raw":
            yield packet.name


"""
----------
CountTree stuff
----------
"""


@dataclass(order=True)
class CountTree:
    name: str
    count: int = 0
    next_layer: list[CountTree] = field(default_factory=list)
    next_layer_strs: list[str] = field(default_factory=list)

    def update_path(self, path: list[str]):
        self.count += 1
        if not path:
            return

        if path[0] in self.next_layer_strs:
            branch_index = self.next_layer_strs.index(path[0])
        else:
            self.next_layer.append(CountTree(name=path[0]))
            self.next_layer_strs.append(path[0])
            branch_index = len(self.next_layer) - 1

        self.next_layer[branch_index].update_path(path[1:])

    def __str__(self) -> str:
        return self.__generate_layer(self, "")

    def __generate_layer(
        self, count_tree: CountTree, current_output: str, depth: int = 0
    ) -> str:
        for branch in sorted(count_tree.next_layer):
            current_output += (
                "    " * (depth - 1)
                + (f" |--" if depth else "")
                + f"{branch.name:<20.20}        {branch.count:,}\n"
            )
            if branch.next_layer:
                current_output = self.__generate_layer(
                    branch, current_output, depth + 1
                )
        return current_output


"""
----------
Live Stats Updating
----------
"""


def update_stats():
    global console, protocol_count, updating
    console = curses.initscr()
    console.scrollok(True)
    console.idlok(True)
    while updating:
        console.erase()
        console.addstr(page_title)
        console.addstr(page_title_edge)
        console.addstr(str(protocol_count))
        console.addstr(f"{protocol_count.count:,}\n")
        console.refresh()
        time.sleep(0.1)
    curses.endwin()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        "pcap_info", description="Help with NCCD CW3 by auto-analysing the PCAP file"
    )
    parser.add_argument(
        "-p",
        "--pcap",
        default=str(Path.home() / "Downloads" / "CW3 PCAP FIle.pcap"),
        help=f"The PCAP file to analyse. Default is {Path.home()}/Downloads/CW3 PCAP FIle.pcap.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="pcap-output.txt",
        help="Where to output the analysis. Default is pcap-output.txt.",
    )
    parser.add_argument(
        "-hl",
        "--headless",
        action="store_true",
        help="Use this flag to not have the live stats updates. Might run a little faster?",
    )
    args = parser.parse_args()

    if len(sys.argv) == 1:
        print("You can also run `pcap_info.py -h` to change the default options")
        time.sleep(1)
    page_title = f"Analysing {args.pcap}\n"
    page_title_edge = "-" * len(page_title) + "\n"

    try:
        packets = PcapReader(args.pcap)
    except Exception as e:
        print(f"ERROR: {e}.\nTrying to read {args.pcap}.", file=sys.stderr)
        quit()

    protocol_count = CountTree(name="Total")

    arp_count = {}
    icmp_count = {}
    snmp_info = []
    port_info = {}
    mac_to_ip = {}

    h_to_h = {}

    updating = True

    if not args.headless:
        update_thread = threading.Thread(target=update_stats)
        update_thread.start()

    for packet in packets:
        protocols = list(get_packet_layers(packet))
        protocol_count.update_path(protocols)

        if packet.haslayer(SNMPresponse):
            if isinstance(packet[SNMPvarbind].value, ASN1_IPADDRESS):
                snmp_info.append(packet[SNMPvarbind].value.val)

        if packet.haslayer(ARP):
            if packet[ARP].op == 2:
                continue
            if packet[ARP].psrc not in arp_count.keys():
                arp_count[packet[ARP].psrc] = {packet[ARP].pdst: 1}
            elif packet[ARP].pdst not in arp_count[packet[ARP].psrc].keys():
                arp_count[packet[ARP].psrc][packet[ARP].pdst] = 1
            else:
                arp_count[packet[ARP].psrc][packet[ARP].pdst] += 1

        if packet.haslayer(ICMP):
            icmp_key = f"{packet[IP].src}-{packet[IP].dst}"
            type_code = packet.sprintf("%ICMP.type%:%ICMP.code%")
            if packet[IP].src not in icmp_count.keys():
                icmp_count[packet[IP].src] = {packet[IP].dst: {type_code: 1}}
            elif packet[IP].dst not in icmp_count[packet[IP].src].keys():
                icmp_count[packet[IP].src][packet[IP].dst] = {type_code: 1}
            elif type_code not in icmp_count[packet[IP].src][packet[IP].dst].keys():
                icmp_count[packet[IP].src][packet[IP].dst][type_code] = 1
            else:
                icmp_count[packet[IP].src][packet[IP].dst][type_code] += 1

        if packet.haslayer(IP) and packet[IP].version == 4:
            if packet.dst not in mac_to_ip.keys():
                mac_to_ip[packet.dst] = {packet[IP].dst}
            else:
                mac_to_ip[packet.dst].add(packet[IP].dst)

            if packet.src not in mac_to_ip.keys():
                mac_to_ip[packet.src] = {packet[IP].src}
            else:
                mac_to_ip[packet.src].add(packet[IP].src)

            protocol = packet.sprintf("%IP.proto%")

            if packet.haslayer(TCP) and packet[TCP].flags & 4:
                protocol = protocol + "-error"

            port_layer = (
                TCP if packet.haslayer(TCP) else UDP if packet.haslayer(UDP) else None
            )
            if port_layer:
                port_key = packet[port_layer].dport
                if packet[IP].dst not in port_info.keys():
                    port_info[packet[IP].dst] = {port_key: 1}
                elif port_key not in port_info[packet[IP].dst].keys():
                    port_info[packet[IP].dst][port_key] = 1
                else:
                    port_info[packet[IP].dst][port_key] += 1

            if packet[IP].src not in h_to_h.keys():
                h_to_h[packet[IP].src] = {packet[IP].dst: {protocol: 1}}
            elif packet[IP].dst not in h_to_h[packet[IP].src].keys():
                h_to_h[packet[IP].src][packet[IP].dst] = {protocol: 1}
            elif protocol not in h_to_h[packet[IP].src][packet[IP].dst].keys():
                h_to_h[packet[IP].src][packet[IP].dst][protocol] = 1
            else:
                h_to_h[packet[IP].src][packet[IP].dst][protocol] += 1
        if packet.haslayer(Dot1Q):
            packet.show()

    updating = False

    if not args.headless:
        update_thread.join()

    print("Done!")

    print(protocol_count)

    file = open(args.output, "w+")

    dict_to_file(h_to_h, title="Host to Host")
    dict_to_file(icmp_count, title="ICMP", sub="Maybe shows VLANs?")

    check_ICMP(icmp_count)

    export_ports(port_info)
    dict_to_file(arp_count, title="ARP", sub="Could show stuff like routers?")
    output_mac_to_ip(mac_to_ip)

    file.write(generate_title("SNMP", "Can show subnets"))
    for finding in snmp_info:
        file.write(f"Found address {finding}\n")

    file.write("\n\nOverview\n----------\n")
    file.write(str(protocol_count))
    file.write(f"\n{protocol_count.count:,}\n")

    file.close()
    print(f"Output to {args.output}")
