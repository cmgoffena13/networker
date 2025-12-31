import structlog
from pendulum import now
from rich.table import Table
from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, IPv6, Packet, Raw
from scapy.layers.inet6 import (
    ICMPv6EchoReply,
    ICMPv6EchoRequest,
    ICMPv6MLQuery2,
    ICMPv6MLReport2,
    ICMPv6ND_NA,
    ICMPv6ND_NS,
)
from scapy.layers.l2 import Ether

from src.cli.console import console
from src.database.device import db_list_devices
from src.models.packet import Packet as PacketModel
from src.protocol import Protocol

logger = structlog.getLogger(__name__)


class PacketHandler:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.devices = db_list_devices()
        self.local_ips = {device.ip_address for device in self.devices}
        self.local_mac_addresses_mapping = {
            device.mac_address: device.ip_address for device in self.devices
        }
        self.ip_to_device_mapping = {
            device.ip_address: device.device_name for device in self.devices
        }
        self.mac_to_device_mapping = {
            device.mac_address: device.device_name for device in self.devices
        }
        if not self.verbose:
            self.table = self._echo_headers()

    def _extract_arp_info(self, arp: ARP, packet_model: PacketModel) -> PacketModel:
        packet_model.request = arp.op == 1
        packet_model.transport_protocol = Protocol.ARP
        packet_model.source_ip = str(arp.psrc)
        packet_model.destination_ip = str(arp.pdst)

        if arp.op == 1:
            message = f"Who is IP Address {arp.pdst}?"
        else:
            message = f"I am IP Address {arp.psrc}"

        additional_data = {"message": message}

        packet_model.additional_data = additional_data
        return packet_model

    def _extract_ipv6_tcp_info(
        self, tcp: TCP, ipv6_layer: IPv6, packet_model: PacketModel
    ) -> PacketModel:
        packet_model.request = bool(tcp.flags & 0x02)
        packet_model.transport_protocol = Protocol.TCP
        packet_model.source_ip = str(ipv6_layer.src)
        packet_model.destination_ip = str(ipv6_layer.dst)
        packet_model.source_port = tcp.sport
        packet_model.destination_port = tcp.dport
        return packet_model

    def _extract_ipv6_icmp_info(
        self, icmpv6: Packet, ipv6_layer: IPv6, packet_model: PacketModel
    ) -> PacketModel:
        packet_model.transport_protocol = Protocol.ICMP
        packet_model.source_ip = str(ipv6_layer.src)
        packet_model.destination_ip = str(ipv6_layer.dst)
        packet_model.request = False

        if isinstance(icmpv6, ICMPv6ND_NS):
            icmp_type = "ND Neighbor Solicitation"
            packet_model.request = True
            if hasattr(icmpv6, "tgt"):
                target = str(icmpv6.tgt)
                packet_model.additional_data = {
                    "message": f"Who has IPv6 address {target}? Please send your MAC."
                }
        elif isinstance(icmpv6, ICMPv6ND_NA):
            icmp_type = "ND Neighbor Advertisement"
            if hasattr(icmpv6, "tgt"):
                target = str(icmpv6.tgt)
                packet_model.additional_data = {
                    "message": f"I am IPv6 address {target}"
                }
        elif isinstance(icmpv6, ICMPv6EchoRequest):
            icmp_type = "Echo Request"
            packet_model.request = True
        elif isinstance(icmpv6, ICMPv6EchoReply):
            icmp_type = "Echo Reply"
        elif isinstance(icmpv6, ICMPv6MLQuery2):
            icmp_type = "MLD Query"
        elif isinstance(icmpv6, ICMPv6MLReport2):
            icmp_type = "MLD Report"
        elif hasattr(icmpv6, "type"):
            icmp_type = f"ICMPv6 Type {icmpv6.type}"
        else:
            icmp_type = "ICMPv6"

        packet_model.application_protocol = icmp_type
        return packet_model

    def _extract_ipv6_udp_info(
        self, udp: UDP, ipv6_layer: IPv6, packet_model: PacketModel
    ) -> PacketModel:
        packet_model.transport_protocol = Protocol.UDP
        packet_model.source_ip = str(ipv6_layer.src) if ipv6_layer.src else None
        packet_model.destination_ip = str(ipv6_layer.dst) if ipv6_layer.dst else None
        packet_model.source_port = udp.sport
        packet_model.destination_port = udp.dport
        packet_model.request = False
        return packet_model

    def _extract_igmp_info(
        self, ip_layer: IP, packet_model: PacketModel
    ) -> PacketModel:
        packet_model.transport_protocol = Protocol.IGMP
        packet_model.source_ip = str(ip_layer.src)
        packet_model.destination_ip = str(ip_layer.dst)
        packet_model.request = False
        packet_model.application_protocol = "IGMP"
        return packet_model

    def _extract_icmp_info(
        self, icmp: ICMP, ip_layer: IP, packet_model: PacketModel
    ) -> PacketModel:
        packet_model.transport_protocol = Protocol.ICMP
        packet_model.source_ip = str(ip_layer.src)
        packet_model.destination_ip = str(ip_layer.dst)
        packet_model.request = False

        icmp_type = None
        if icmp.type == 8:
            icmp_type = "Echo Request"
            packet_model.request = True
        elif icmp.type == 0:
            icmp_type = "Echo Reply"
        elif icmp.type == 3:
            icmp_type = "Destination Unreachable"
        elif icmp.type == 11:
            icmp_type = "Time Exceeded"
        elif hasattr(icmp, "type"):
            icmp_type = f"ICMP Type {icmp.type}"
        else:
            icmp_type = "ICMP"

        packet_model.application_protocol = icmp_type
        return packet_model

    def _extract_tcp_info(
        self, tcp: TCP, ip_layer: IP, packet_model: PacketModel
    ) -> PacketModel:
        packet_model.request = bool(tcp.flags & 0x02)
        packet_model.transport_protocol = Protocol.TCP
        packet_model.source_ip = str(ip_layer.src)
        packet_model.destination_ip = str(ip_layer.dst)
        packet_model.source_port = tcp.sport
        packet_model.destination_port = tcp.dport
        return packet_model

    def _extract_udp_info(
        self, udp: UDP, ip_layer: IP, packet_model: PacketModel
    ) -> PacketModel:
        packet_model.transport_protocol = Protocol.UDP
        packet_model.source_ip = str(ip_layer.src) if ip_layer.src else None
        packet_model.destination_ip = str(ip_layer.dst) if ip_layer.dst else None
        packet_model.source_port = udp.sport
        packet_model.destination_port = udp.dport
        packet_model.request = False

        return packet_model

    def _extract_udp_dns_info(
        self, udp: UDP, dns: DNS, ip_layer: IP | IPv6, packet_model: PacketModel
    ) -> PacketModel:
        packet_model.request = dns.qr == 0
        packet_model.transport_protocol = Protocol.UDP
        packet_model.source_ip = ip_layer.src
        packet_model.destination_ip = ip_layer.dst
        packet_model.source_port = udp.sport
        packet_model.destination_port = udp.dport
        packet_model.application_protocol = "DNS"

        if dns.qr == 0 and dns.qd:
            try:
                if hasattr(dns.qd, "qname"):
                    query_name = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(
                        "."
                    )
                    packet_model.additional_data = {"query_name": query_name}
            except (AttributeError, UnicodeDecodeError):
                pass
        elif dns.qr == 1:
            answers = []
            if dns.an:
                for rr in dns.an:
                    try:
                        if hasattr(rr, "rdata"):
                            rdata = rr.rdata
                            if isinstance(rdata, bytes):
                                rdata = rdata.decode("utf-8", errors="ignore")
                            elif isinstance(rdata, str):
                                pass
                            else:
                                rdata = str(rdata)
                            answers.append(rdata)
                        elif hasattr(rr, "rrname"):
                            answer_str = f"{rr.rrname.decode('utf-8', errors='ignore').rstrip('.')}"
                            if hasattr(rr, "type") and rr.type:
                                answer_str += f" (type {rr.type})"
                            answers.append(answer_str)
                    except (AttributeError, UnicodeDecodeError, TypeError):
                        pass
            if dns.ns:
                for rr in dns.ns:
                    try:
                        if hasattr(rr, "rdata"):
                            rdata = rr.rdata
                            if isinstance(rdata, bytes):
                                rdata = rdata.decode("utf-8", errors="ignore")
                            answers.append(rdata)
                    except (AttributeError, UnicodeDecodeError, TypeError):
                        pass
            if dns.ar:
                for rr in dns.ar:
                    try:
                        if hasattr(rr, "rdata"):
                            rdata = rr.rdata
                            if isinstance(rdata, bytes):
                                rdata = rdata.decode("utf-8", errors="ignore")
                            answers.append(rdata)
                    except (AttributeError, UnicodeDecodeError, TypeError):
                        pass
            if answers:
                packet_model.additional_data = {"answers": answers}

        return packet_model

    def _extract_udp_mdns_info(
        self, udp: UDP, dns: DNS, ip_layer: IP | IPv6, packet_model: PacketModel
    ) -> PacketModel:
        packet_model.request = dns.qr == 0
        packet_model.transport_protocol = Protocol.UDP
        packet_model.source_ip = str(ip_layer.src) if ip_layer.src else None
        packet_model.destination_ip = str(ip_layer.dst) if ip_layer.dst else None
        packet_model.source_port = udp.sport
        packet_model.destination_port = udp.dport
        packet_model.application_protocol = "mDNS"

        if dns.qr == 0 and dns.qd:
            try:
                if hasattr(dns.qd, "qname"):
                    query_name = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(
                        "."
                    )
                    packet_model.additional_data = {"query_name": query_name}
            except (AttributeError, UnicodeDecodeError):
                pass
        elif dns.qr == 1:
            answers = []
            if dns.an:
                for rr in dns.an:
                    try:
                        if hasattr(rr, "rdata"):
                            rdata = rr.rdata
                            if isinstance(rdata, bytes):
                                rdata = rdata.decode("utf-8", errors="ignore")
                            elif isinstance(rdata, str):
                                pass
                            else:
                                rdata = str(rdata)
                            answers.append(rdata)
                        elif hasattr(rr, "rrname"):
                            answer_str = f"{rr.rrname.decode('utf-8', errors='ignore').rstrip('.')}"
                            if hasattr(rr, "type") and rr.type:
                                answer_str += f" (type {rr.type})"
                            answers.append(answer_str)
                    except (AttributeError, UnicodeDecodeError, TypeError):
                        pass
            if dns.ns:
                for rr in dns.ns:
                    try:
                        if hasattr(rr, "rdata"):
                            rdata = rr.rdata
                            if isinstance(rdata, bytes):
                                rdata = rdata.decode("utf-8", errors="ignore")
                            answers.append(rdata)
                    except (AttributeError, UnicodeDecodeError, TypeError):
                        pass
            if dns.ar:
                for rr in dns.ar:
                    try:
                        if hasattr(rr, "rdata"):
                            rdata = rr.rdata
                            if isinstance(rdata, bytes):
                                rdata = rdata.decode("utf-8", errors="ignore")
                            answers.append(rdata)
                    except (AttributeError, UnicodeDecodeError, TypeError):
                        pass
            if answers:
                packet_model.additional_data = {"answers": answers}

        return packet_model

    def _extract_tcp_http_info(
        self, tcp: TCP, ip_layer: IP | IPv6, packet: Packet, packet_model: PacketModel
    ) -> PacketModel:
        packet_model.transport_protocol = Protocol.TCP
        packet_model.source_ip = str(ip_layer.src)
        packet_model.destination_ip = str(ip_layer.dst)
        packet_model.source_port = tcp.sport
        packet_model.destination_port = tcp.dport

        if tcp.dport == 443 or tcp.sport == 443:
            packet_model.application_protocol = "HTTPS"
        else:
            packet_model.application_protocol = "HTTP"

        if packet.haslayer(Raw):
            raw = packet[Raw]
            payload_bytes = bytes(raw.load)
            try:
                payload_str = payload_bytes.decode("utf-8", errors="ignore")
                if payload_str.startswith(
                    ("GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ")
                ):
                    packet_model.request = True
                    lines = payload_str.split("\r\n", 1)
                    if lines:
                        request_line = lines[0]
                        parts = request_line.split(" ", 2)
                        if len(parts) >= 2:
                            method = parts[0]
                            path = parts[1] if len(parts) > 1 else ""
                            packet_model.additional_data = {
                                "method": method,
                                "path": path,
                            }
                elif payload_str.startswith("HTTP/"):
                    packet_model.request = False
                    lines = payload_str.split("\r\n", 1)
                    if lines:
                        status_line = lines[0]
                        parts = status_line.split(" ", 2)
                        if len(parts) >= 3:
                            status_code = parts[1]
                            status_message = parts[2] if len(parts) > 2 else ""
                            packet_model.additional_data = {
                                "status_code": status_code,
                                "status_message": status_message,
                            }
            except (ValueError, UnicodeDecodeError):
                pass

        return packet_model

    def _echo_headers(self) -> Table:
        table = Table(
            show_header=False,
            header_style="bold green",
            expand=True,
            show_lines=False,
            box=None,
        )
        table.add_column("timestamp", style="dim green", width=26, no_wrap=True)
        table.add_column(
            "transport_protocol", style="bold bright_green", width=3, no_wrap=True
        )
        table.add_column("internal_ip", width=18, no_wrap=False)
        table.add_column("direction", width=2)
        table.add_column("external_ip", width=18, no_wrap=False)
        table.add_column("application_protocol", width=5)
        table.add_column("additional_data", style="cyan", width=20)
        return table

    def _console_determine_ip_direction(
        self, packet_model: PacketModel
    ) -> tuple[str, str, str]:
        source_port = str(packet_model.source_port) if packet_model.source_port else ""
        destination_port = (
            str(packet_model.destination_port) if packet_model.destination_port else ""
        )

        source_ip = packet_model.source_ip

        label = None
        if packet_model.destination_mac.lower() == "ff:ff:ff:ff:ff:ff":
            label = "ARP Broadcast"
        elif (
            packet_model.application_protocol == "mDNS"
            or packet_model.destination_port == 5353
            or packet_model.source_port == 5353
        ):
            label = "mDNS Multicast"
        elif packet_model.destination_mac.lower().startswith("33:33") or (
            packet_model.destination_ip
            and ":" in packet_model.destination_ip
            and packet_model.destination_ip.startswith("ff")
        ):
            label = "IPv6 Multicast"
        elif packet_model.destination_ip and packet_model.destination_ip.startswith(
            "224."
        ):
            label = "IPv4 Multicast"

        if label:
            destination_ip = f"[bold purple]{label}[/bold purple]"
        else:
            destination_ip = packet_model.destination_ip

        if not source_ip or not destination_ip:
            logger.warning(
                f"Blank IP detected - source_ip: {source_ip or 'None'}, "
                f"destination_ip: {destination_ip or 'None'}, "
                f"source_mac: {packet_model.source_mac}, "
                f"destination_mac: {packet_model.destination_mac}, "
                f"protocol: {packet_model.transport_protocol.value}"
            )
            return "", "", ""  # Skip displaying packets with blank IPs

        source_is_internal = source_ip in self.local_ips
        dest_is_internal = destination_ip in self.local_ips

        if source_is_internal and not dest_is_internal:
            internal_ip = source_ip
            internal_port = source_port
            internal_mac = packet_model.source_mac
            external_ip = destination_ip
            external_port = destination_port
            external_mac = packet_model.destination_mac
            direction = "->"
        elif dest_is_internal and not source_is_internal:
            internal_ip = destination_ip
            internal_port = destination_port
            internal_mac = packet_model.destination_mac
            external_ip = source_ip
            external_port = source_port
            external_mac = packet_model.source_mac
            direction = "<-"
        elif source_is_internal and dest_is_internal:
            if packet_model.request:
                internal_ip = source_ip
                internal_port = source_port
                internal_mac = packet_model.source_mac
                external_ip = destination_ip
                external_port = destination_port
                external_mac = packet_model.destination_mac
                direction = "->"
            else:
                internal_ip = destination_ip
                internal_port = destination_port
                internal_mac = packet_model.destination_mac
                external_ip = source_ip
                external_port = source_port
                external_mac = packet_model.source_mac
                direction = "<-"
        else:
            internal_ip = source_ip
            internal_port = source_port
            internal_mac = packet_model.source_mac
            external_ip = destination_ip
            external_port = destination_port
            external_mac = packet_model.destination_mac
            direction = "->" if packet_model.request else "<-"

        def _format_ip_string(ip: str, port: str, device_name: str | None) -> str:
            name_str = f" ({device_name})" if device_name else ""
            is_special = ip.startswith("[bold purple]")
            if port and not is_special:
                return f"{ip}:[yellow]{port}[/yellow]{name_str}"
            return f"{ip}{name_str}"

        internal_device_name = None
        if not internal_ip.startswith("[bold purple]"):
            internal_device_name = self.ip_to_device_mapping.get(internal_ip)
            if not internal_device_name and internal_mac:
                internal_device_name = self.mac_to_device_mapping.get(internal_mac)

        external_device_name = None
        if not external_ip.startswith("[bold purple]"):
            external_device_name = self.ip_to_device_mapping.get(external_ip)
            if not external_device_name and external_mac:
                external_device_name = self.mac_to_device_mapping.get(external_mac)
        internal_str = _format_ip_string(
            internal_ip, internal_port, internal_device_name
        )
        external_str = _format_ip_string(
            external_ip, external_port, external_device_name
        )

        if direction == "->":
            direction_formatted = f"[cyan]{direction}[/cyan]"
        else:
            direction_formatted = f"[red]{direction}[/red]"

        return internal_str, direction_formatted, external_str

    def echo_packet(self, packet_model: PacketModel) -> None:
        additional_data_str = (
            str(packet_model.additional_data) if packet_model.additional_data else ""
        )
        timestamp = packet_model.timestamp.format("YYYY-MM-DD HH:mm:ss:SSSSSS")

        internal_str, direction_formatted, external_str = (
            self._console_determine_ip_direction(packet_model)
        )

        protocol_value = packet_model.transport_protocol.value
        if protocol_value == "TCP":
            protocol_formatted = f"[bold green]{protocol_value}[/bold green]"
        elif protocol_value == "UDP":
            protocol_formatted = f"[yellow]{protocol_value}[/yellow]"
        elif protocol_value in ("ARP", "ICMP", "IGMP"):
            protocol_formatted = f"[bold red]{protocol_value}[/bold red]"
        else:
            protocol_formatted = protocol_value

        self.table.add_row(
            str(timestamp),
            protocol_formatted,
            internal_str,
            direction_formatted,
            external_str,
            packet_model.application_protocol or "",
            additional_data_str,
        )
        console.print(self.table)

    def handle_packet(self, packet: Packet) -> None:
        if not packet.haslayer(Ether):
            return

        ether = packet[Ether]
        logger.debug(f"{ether.src} -> {ether.dst} - Packet Ether: {ether}")
        packet_model = PacketModel(
            timestamp=now(),
            request=False,
            source_mac=ether.src,
            destination_mac=ether.dst,
            ethernet_type=hex(ether.type)[2:].upper().zfill(4),
            transport_protocol=Protocol.TCP,
            payload_length=0,
        )
        if packet.haslayer(Raw):
            raw = packet[Raw]
            payload_bytes = bytes(raw.load)
            packet_model.payload_length = len(payload_bytes)
            if packet_model.payload_length > 0 and packet_model.payload_length <= 16384:
                packet_model.payload_hex = payload_bytes.hex()
            else:
                logger.warning(
                    f"Payload length is too long: {packet_model.payload_length}"
                )

        if (
            packet.haslayer(ARP)
            and not packet.haslayer(IP)
            and not packet.haslayer(IPv6)
        ):
            packet_model = self._extract_arp_info(packet[ARP], packet_model)
        elif packet.haslayer(IPv6):
            ipv6_layer = packet[IPv6]
            logger.debug(
                f"{ipv6_layer.src} -> {ipv6_layer.dst} - IPv6 Layer: {ipv6_layer}"
            )
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                logger.debug(f"\t\t{tcp.sport} -> {tcp.dport} - TCP Layer: {tcp}")
                if tcp.dport in (80, 443) or tcp.sport in (80, 443):
                    packet_model = self._extract_tcp_http_info(
                        tcp, ipv6_layer, packet, packet_model
                    )
                else:
                    packet_model = self._extract_ipv6_tcp_info(
                        tcp, ipv6_layer, packet_model
                    )
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                logger.debug(f"\t\t{udp.sport} -> {udp.dport} - UDP Layer: {udp}")
                if packet.haslayer(DNS):
                    logger.debug(f"\t\t\tDNS Layer: {packet[DNS]}")
                    if udp.dport == 5353 or udp.sport == 5353:
                        packet_model = self._extract_udp_mdns_info(
                            udp, packet[DNS], ipv6_layer, packet_model
                        )
                    if udp.dport == 53 or udp.sport == 53:
                        packet_model = self._extract_udp_dns_info(
                            udp, packet[DNS], ipv6_layer, packet_model
                        )
                else:
                    packet_model = self._extract_ipv6_udp_info(
                        udp, ipv6_layer, packet_model
                    )
            elif (
                packet.haslayer(ICMPv6ND_NS)
                or packet.haslayer(ICMPv6ND_NA)
                or packet.haslayer(ICMPv6EchoRequest)
                or packet.haslayer(ICMPv6EchoReply)
                or packet.haslayer(ICMPv6MLQuery2)
                or packet.haslayer(ICMPv6MLReport2)
            ):
                # Handle ICMPv6 packets
                icmpv6 = None
                if packet.haslayer(ICMPv6ND_NS):
                    icmpv6 = packet[ICMPv6ND_NS]
                elif packet.haslayer(ICMPv6ND_NA):
                    icmpv6 = packet[ICMPv6ND_NA]
                elif packet.haslayer(ICMPv6EchoRequest):
                    icmpv6 = packet[ICMPv6EchoRequest]
                elif packet.haslayer(ICMPv6EchoReply):
                    icmpv6 = packet[ICMPv6EchoReply]
                elif packet.haslayer(ICMPv6MLQuery2):
                    icmpv6 = packet[ICMPv6MLQuery2]
                elif packet.haslayer(ICMPv6MLReport2):
                    icmpv6 = packet[ICMPv6MLReport2]

                if icmpv6:
                    packet_model = self._extract_ipv6_icmp_info(
                        icmpv6, ipv6_layer, packet_model
                    )
            else:
                return
        elif packet.haslayer(IP) and not packet.haslayer(IPv6):
            ip_layer = packet[IP]
            logger.debug(f"{ip_layer.src} -> {ip_layer.dst} - IP Layer: {ip_layer}")
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                logger.debug(f"\t\t{tcp.sport} -> {tcp.dport} - TCP Layer: {tcp}")
                if tcp.dport in (80, 443) or tcp.sport in (80, 443):
                    packet_model = self._extract_tcp_http_info(
                        tcp, ip_layer, packet, packet_model
                    )
                else:
                    packet_model = self._extract_tcp_info(tcp, ip_layer, packet_model)
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                logger.debug(f"\t\t{udp.sport} -> {udp.dport} - UDP Layer: {udp}")
                if packet.haslayer(DNS):
                    logger.debug(f"\t\t\tDNS Layer: {packet[DNS]}")
                    if udp.dport == 5353 or udp.sport == 5353:
                        packet_model = self._extract_udp_mdns_info(
                            udp, packet[DNS], ip_layer, packet_model
                        )
                    if udp.dport == 53 or udp.sport == 53:
                        packet_model = self._extract_udp_dns_info(
                            udp, packet[DNS], ip_layer, packet_model
                        )
                else:
                    packet_model = self._extract_udp_info(udp, ip_layer, packet_model)
            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                logger.debug(f"\t\tICMP Layer: {icmp}")
                packet_model = self._extract_icmp_info(icmp, ip_layer, packet_model)
            elif ip_layer.proto == 2:
                logger.debug(f"\t\tIGMP Layer: protocol 2")
                packet_model = self._extract_igmp_info(ip_layer, packet_model)

        if packet_model.source_ip is None or packet_model.destination_ip is None:
            logger.warning(
                f"Blank IP detected - source_ip: {packet_model.source_ip or 'None'}, "
                f"destination_ip: {packet_model.destination_ip or 'None'}, "
                f"source_mac: {packet_model.source_mac}, "
                f"destination_mac: {packet_model.destination_mac}, "
                f"protocol: {packet_model.transport_protocol.value}"
            )
            logger.warning(f"Packet: {packet}")
            logger.warning(f"Packet Model: {packet_model}")
            return

        if not self.verbose:
            self.echo_packet(packet_model)
