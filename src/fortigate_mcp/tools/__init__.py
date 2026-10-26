"""FortiGate MCP tools implementation."""

from .base import FortiGateTool
from .catalog import CatalogTools
from .generic import GenericTools
from .device import DeviceTools
from .dhcp import DhcpTools
from .firewall import FirewallTools
from .network import NetworkTools
from .routing import RoutingTools
from .security import SecurityProfileTools
from .system import SystemTools
from .users import UserTools
from .virtual_ip import VirtualIPTools
from .vpn import VpnTools

__all__ = [
    "FortiGateTool",
    "CatalogTools",
    "GenericTools",
    "DeviceTools",
    "DhcpTools",
    "FirewallTools",
    "NetworkTools",
    "RoutingTools",
    "SecurityProfileTools",
    "SystemTools",
    "UserTools",
    "VirtualIPTools",
    "VpnTools",
]
