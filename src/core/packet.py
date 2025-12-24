from typing import Tuple

from scapy.all import Packet

from src.cli.console import echo
from src.database.device import db_list_devices


class PacketHandler:
    def __init__(self):
        self.devices = db_list_devices()
        self.local_ips = {device.ip_address for device in self.devices}

    def _format_ip_direction(
        self, src_ip: str, dst_ip: str, arrow: str = "->"
    ) -> Tuple[str, str, str]:
        src_is_local = src_ip in self.local_ips
        dst_is_local = dst_ip in self.local_ips

        if src_is_local and not dst_is_local:
            # Local -> External
            return (src_ip, arrow, dst_ip)
        elif dst_is_local and not src_is_local:
            # External <- Local (reversed)
            return (dst_ip, "<-", src_ip)
        else:
            # Both local or both external, keep original direction
            return (src_ip, arrow, dst_ip)

    def handle_packet(self, packet: Packet) -> None:
        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst
            if packet.haslayer("UDP") and packet.haslayer("DNS"):
                udp = packet["UDP"]
                dns = packet["DNS"]
                # mDNS (multicast DNS) on port 5353
                if udp.dport == 5353 or udp.sport == 5353:
                    # PTR query (type=12) for service discovery
                    if dns.qr == 0 and dns.qd and dns.qd.qtype == 12:
                        hostname = dns.qd.qname.decode("utf-8").rstrip(".")
                        left_ip, arrow, right_ip = self._format_ip_direction(
                            src_ip, dst_ip
                        )
                        echo(f"mDNS Query: {left_ip} {arrow} {right_ip} | {hostname}")
                    # Response with actual hostname
                    elif dns.qr == 1 and dns.an:
                        for rr in dns.an:
                            if rr.type == 12:  # PTR record
                                hostname = rr.rdata.decode("utf-8").rstrip(".")
                                left_ip, arrow, right_ip = self._format_ip_direction(
                                    src_ip, dst_ip
                                )
                                echo(
                                    f"mDNS Response: {left_ip} {arrow} {right_ip} | {hostname.split('.')[0]}"
                                )
                                break
                else:
                    # Regular DNS
                    if dns.qr == 0:
                        query_name = (
                            dns.qd.qname.decode("utf-8").rstrip(".")
                            if dns.qd
                            else "unknown"
                        )
                        left_ip, arrow, right_ip = self._format_ip_direction(
                            src_ip, dst_ip
                        )
                        echo(f"DNS: {left_ip} {arrow} {right_ip} | {query_name}")
            elif packet.haslayer("TCP"):
                src_port = packet["TCP"].sport
                dst_port = packet["TCP"].dport
                left_ip, arrow, right_ip = self._format_ip_direction(src_ip, dst_ip)
                # If direction was reversed, swap ports too
                if arrow == "<-":
                    left_port, right_port = dst_port, src_port
                else:
                    left_port, right_port = src_port, dst_port
                echo(f"TCP: {left_ip}:{left_port} {arrow} {right_ip}:{right_port}")
            elif packet.haslayer("UDP") and not packet.haslayer("DNS"):
                # Only show UDP if it's not DNS (DNS is handled above)
                src_port = packet["UDP"].sport
                dst_port = packet["UDP"].dport
                left_ip, arrow, right_ip = self._format_ip_direction(src_ip, dst_ip)
                # If direction was reversed, swap ports too
                if arrow == "<-":
                    left_port, right_port = dst_port, src_port
                else:
                    left_port, right_port = src_port, dst_port
                echo(f"UDP: {left_ip}:{left_port} {arrow} {right_ip}:{right_port}")
            elif packet.haslayer("ARP"):
                arp_src = packet["ARP"].psrc
                arp_dst = packet["ARP"].pdst
                left_ip, arrow, right_ip = self._format_ip_direction(arp_src, arp_dst)
                echo(f"ARP: {left_ip} {arrow} {right_ip}")
