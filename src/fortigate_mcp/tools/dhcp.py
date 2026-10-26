"""DHCP server, reservation and lease tools for FortiGate MCP."""
import ipaddress
import re
from typing import Any, Dict, List, Optional

from mcp.types import TextContent as Content

from .base import FortiGateTool

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})$")


def normalize_mac(mac: str) -> str:
    """Validate a MAC address and normalize it to lowercase colon form."""
    if not isinstance(mac, str):
        raise ValueError("mac must be a string")
    match = _MAC_RE.match(mac.strip())
    if not match:
        raise ValueError("mac is not a valid MAC address (expected aa:bb:cc:dd:ee:ff)")
    return ":".join(part.lower() for part in match.groups())


def validate_ipv4(ip: str, field_name: str = "ip") -> str:
    """Validate an IPv4 address literal."""
    try:
        return str(ipaddress.IPv4Address(str(ip).strip()))
    except (ipaddress.AddressValueError, ValueError):
        raise ValueError(f"{field_name} is not a valid IPv4 address")


class DhcpTools(FortiGateTool):
    """Tools for FortiGate DHCP servers, reservations and leases."""

    def list_dhcp_servers(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List DHCP servers with ranges and reservations."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            servers = api_client.get_dhcp_servers(vdom=vdom)
            return self._format_response(servers, "dhcp_servers")
        except Exception as e:
            return self._handle_error("list dhcp servers", device_id, e)

    def list_dhcp_leases(self, device_id: str, interface: Optional[str] = None,
                         vdom: Optional[str] = None) -> List[Content]:
        """List active DHCP leases (optionally for one interface)."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            leases = api_client.get_dhcp_leases(vdom=vdom)
            return self._format_response(leases, "dhcp_leases", interface=interface)
        except Exception as e:
            return self._handle_error("list dhcp leases", device_id, e)

    @staticmethod
    def _servers(api_client: Any, vdom: Optional[str]) -> List[Dict[str, Any]]:
        data = api_client.get_dhcp_servers(vdom=vdom)
        return [s for s in (data.get("results") or []) if isinstance(s, dict)]

    def _resolve_server(self, api_client: Any, vdom: Optional[str], dhcp_server_id: Optional[str],
                        interface: Optional[str], ip: Optional[str]) -> Dict[str, Any]:
        """Pick the DHCP server by explicit id, by interface, or by the subnet that contains ``ip``."""
        servers = self._servers(api_client, vdom)
        if dhcp_server_id:
            for srv in servers:
                if str(srv.get("id")) == str(dhcp_server_id):
                    return srv
            raise ValueError(f"DHCP server id {self._safe_id(dhcp_server_id)} not found")
        if interface:
            for srv in servers:
                if srv.get("interface") == interface:
                    return srv
            raise ValueError(f"No DHCP server configured on interface {self._safe_id(interface)}")
        if ip:
            target = ipaddress.IPv4Address(ip)
            for srv in servers:
                for rng in srv.get("ip-range", []) or []:
                    try:
                        if ipaddress.IPv4Address(rng.get("start-ip")) <= target <= ipaddress.IPv4Address(rng.get("end-ip")):
                            return srv
                    except (ValueError, TypeError):
                        continue
                try:
                    network = ipaddress.IPv4Network(f"{srv.get('default-gateway')}/{srv.get('netmask')}", strict=False)
                    if target in network:
                        return srv
                except (ValueError, TypeError):
                    continue
            raise ValueError("No DHCP server covers the given ip; pass dhcp_server_id or interface explicitly")
        raise ValueError("Provide dhcp_server_id, interface or ip to identify the DHCP server")

    def create_dhcp_reservation(self, device_id: str, ip: str, mac: str, description: Optional[str] = None,
                                dhcp_server_id: Optional[str] = None, interface: Optional[str] = None,
                                vdom: Optional[str] = None) -> List[Content]:
        """Reserve an IP for a MAC address on a DHCP server.

        The server is chosen by ``dhcp_server_id``, else by ``interface``, else by
        the server whose range/subnet contains ``ip``.
        """
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(ip=ip, mac=mac)
            safe_ip = validate_ipv4(ip)
            safe_mac = normalize_mac(mac)
            api_client = self._get_device_api(device_id)
            server = self._resolve_server(api_client, vdom, dhcp_server_id, interface, safe_ip)
            for res in server.get("reserved-address", []) or []:
                if not isinstance(res, dict):
                    continue
                if str(res.get("ip")) == safe_ip:
                    raise ValueError(f"IP {safe_ip} is already reserved (reservation id {res.get('id')}, mac {res.get('mac')})")
                if str(res.get("mac", "")).lower() == safe_mac:
                    raise ValueError(f"MAC {safe_mac} already has a reservation (id {res.get('id')}, ip {res.get('ip')})")
            payload: Dict[str, Any] = {"ip": safe_ip, "mac": safe_mac, "action": "reserved"}
            if description:
                payload["description"] = description
            api_client.create_dhcp_reservation(str(server.get("id")), payload, vdom=vdom)
            return self._format_operation_result(
                "create dhcp reservation", device_id, True,
                f"Reserved {safe_ip} for {safe_mac} on DHCP server {server.get('id')} (interface {server.get('interface')})",
            )
        except Exception as e:
            return self._handle_error("create dhcp reservation", device_id, e)

    def delete_dhcp_reservation(self, device_id: str, dhcp_server_id: Optional[str] = None,
                                reservation_id: Optional[str] = None, ip: Optional[str] = None,
                                mac: Optional[str] = None, vdom: Optional[str] = None) -> List[Content]:
        """Delete a DHCP reservation, located by reservation_id, ip or mac."""
        try:
            self._validate_device_exists(device_id)
            if not (reservation_id or ip or mac):
                raise ValueError("Provide reservation_id, ip or mac to identify the reservation")
            safe_ip = validate_ipv4(ip) if ip else None
            safe_mac = normalize_mac(mac) if mac else None
            api_client = self._get_device_api(device_id)
            servers = self._servers(api_client, vdom)
            if dhcp_server_id:
                servers = [s for s in servers if str(s.get("id")) == str(dhcp_server_id)]
                if not servers:
                    raise ValueError(f"DHCP server id {self._safe_id(dhcp_server_id)} not found")
            matches = []
            for srv in servers:
                for res in srv.get("reserved-address", []) or []:
                    if not isinstance(res, dict):
                        continue
                    if reservation_id and str(res.get("id")) != str(reservation_id):
                        continue
                    if safe_ip and str(res.get("ip")) != safe_ip:
                        continue
                    if safe_mac and str(res.get("mac", "")).lower() != safe_mac:
                        continue
                    matches.append((srv, res))
            if not matches:
                raise ValueError("No matching DHCP reservation found")
            if len(matches) > 1:
                found = ", ".join(f"server {s.get('id')} id {r.get('id')} ({r.get('ip')})" for s, r in matches)
                raise ValueError(f"Ambiguous: {len(matches)} reservations match ({found}); pass dhcp_server_id and reservation_id")
            server, res = matches[0]
            api_client.delete_dhcp_reservation(str(server.get("id")), str(res.get("id")), vdom=vdom)
            return self._format_operation_result(
                "delete dhcp reservation", device_id, True,
                f"Deleted reservation {res.get('id')} ({res.get('ip')} / {res.get('mac')}) on DHCP server {server.get('id')}",
            )
        except Exception as e:
            return self._handle_error("delete dhcp reservation", device_id, e)

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for DHCP tools."""
        return {
            "name": "dhcp_tools",
            "description": "FortiGate DHCP server, reservation and lease tools",
            "operations": [
                {"name": "list_dhcp_servers", "description": "List DHCP servers and reservations",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "vdom", "type": "string", "required": False}]},
                {"name": "list_dhcp_leases", "description": "List active DHCP leases",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "interface", "type": "string", "required": False},
                                {"name": "vdom", "type": "string", "required": False}]},
                {"name": "create_dhcp_reservation", "description": "Reserve an IP for a MAC address",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "ip", "type": "string", "required": True},
                                {"name": "mac", "type": "string", "required": True},
                                {"name": "description", "type": "string", "required": False},
                                {"name": "dhcp_server_id", "type": "string", "required": False},
                                {"name": "interface", "type": "string", "required": False},
                                {"name": "vdom", "type": "string", "required": False}]},
                {"name": "delete_dhcp_reservation", "description": "Delete a DHCP reservation",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "dhcp_server_id", "type": "string", "required": False},
                                {"name": "reservation_id", "type": "string", "required": False},
                                {"name": "ip", "type": "string", "required": False},
                                {"name": "mac", "type": "string", "required": False},
                                {"name": "vdom", "type": "string", "required": False}]},
            ],
        }
