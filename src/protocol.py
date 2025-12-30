from enum import Enum


class Protocol(str, Enum):
    ARP = "ARP"
    TCP = "TCP"
    UDP = "UDP"
