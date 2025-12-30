import structlog
from pendulum import now
from rich.table import Table
from scapy.all import ARP, DNS, IP, TCP, UDP, Packet, Raw
from scapy.layers.l2 import Ether

from src.cli.console import console
from src.database.device import db_list_devices
from src.models.packet import Packet as PacketModel
from src.protocol import Protocol

logger = structlog.getLogger(__name__)


class PacketHandler:
    def __init__(self):
        self.devices = db_list_devices()
        self.local_ips = {device.ip_address for device in self.devices}
        self.local_mac_addresses_mapping = {
            device.mac_address: device.ip_address for device in self.devices
        }
        self.device_names_mapping = {
            device.ip_address: device.device_name for device in self.devices
        }
        self.table = self._echo_headers()

    def _extract_arp_info(self, arp: ARP, packet_model: PacketModel) -> PacketModel:
        packet_model.request = arp.op == 1
        packet_model.transport_protocol = Protocol.ARP
        packet_model.source_ip = arp.psrc
        packet_model.destination_ip = arp.pdst
        return packet_model

    def _extract_tcp_info(
        self, tcp: TCP, ip_layer: IP, packet_model: PacketModel
    ) -> PacketModel:
        packet_model.request = bool(tcp.flags & 0x02)
        packet_model.transport_protocol = Protocol.TCP
        packet_model.source_ip = ip_layer.src
        packet_model.destination_ip = ip_layer.dst
        packet_model.source_port = tcp.sport
        packet_model.destination_port = tcp.dport
        return packet_model

    def _extract_udp_info(
        self, udp: UDP, ip_layer: IP, packet_model: PacketModel
    ) -> PacketModel:
        packet_model.transport_protocol = Protocol.UDP
        packet_model.source_ip = ip_layer.src
        packet_model.destination_ip = ip_layer.dst
        packet_model.source_port = udp.sport
        packet_model.destination_port = udp.dport
        packet_model.request = False
        return packet_model

    def _extract_udp_dns_info(
        self, udp: UDP, dns: DNS, ip_layer: IP, packet_model: PacketModel
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
        self, udp: UDP, dns: DNS, ip_layer: IP, packet_model: PacketModel
    ) -> PacketModel:
        packet_model.request = dns.qr == 0
        packet_model.transport_protocol = Protocol.UDP
        packet_model.source_ip = ip_layer.src
        packet_model.destination_ip = ip_layer.dst
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
        self, tcp: TCP, ip_layer: IP, packet: Packet, packet_model: PacketModel
    ) -> PacketModel:
        packet_model.transport_protocol = Protocol.TCP
        packet_model.source_ip = ip_layer.src
        packet_model.destination_ip = ip_layer.dst
        packet_model.source_port = tcp.sport
        packet_model.destination_port = tcp.dport
        # Determine if HTTP or HTTPS based on port
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

        if not packet_model.source_ip:
            source_ip = (
                self.local_mac_addresses_mapping.get(packet_model.source_mac) or ""
            )
        else:
            source_ip = packet_model.source_ip
        if not packet_model.destination_ip:
            destination_ip = (
                self.local_mac_addresses_mapping.get(packet_model.destination_mac) or ""
            )
        else:
            destination_ip = packet_model.destination_ip

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

        internal_device_name = self.device_names_mapping.get(internal_ip)
        external_device_name = self.device_names_mapping.get(external_ip)
        internal_name_str = f" ({internal_device_name})" if internal_device_name else ""
        internal_str = (
            f"{internal_ip}:[yellow]{internal_port}[/yellow]{internal_name_str}"
            if internal_port
            else f"{internal_ip}{internal_name_str}"
        )

        external_name_str = f" ({external_device_name})" if external_device_name else ""
        external_str = (
            f"{external_ip}:[yellow]{external_port}[/yellow]{external_name_str}"
            if external_port
            else f"{external_ip}{external_name_str}"
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
        elif protocol_value == "ARP":
            protocol_formatted = f"[red]{protocol_value}[/red]"
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
        console.print("\n")

    def handle_packet(self, packet: Packet) -> None:
        if not packet.haslayer(Ether):
            return

        ether = packet[Ether]
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

        if packet.haslayer(ARP) and not packet.haslayer(IP):
            packet_model = self._extract_arp_info(packet[ARP], packet_model)
        elif packet.haslayer(IP):
            ip_layer = packet[IP]
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                if tcp.dport in (80, 443) or tcp.sport in (80, 443):
                    packet_model = self._extract_tcp_http_info(
                        tcp, ip_layer, packet, packet_model
                    )
                else:
                    packet_model = self._extract_tcp_info(tcp, ip_layer, packet_model)
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                if packet.haslayer(DNS):
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

        self.echo_packet(packet_model)
