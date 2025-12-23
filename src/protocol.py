from enum import Enum


class Protocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
