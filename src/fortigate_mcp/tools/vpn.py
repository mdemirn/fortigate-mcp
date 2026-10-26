"""VPN monitoring tools for FortiGate MCP (read-only)."""
from typing import Any, Dict, List, Optional

from mcp.types import TextContent as Content

from ..validation import validate_object_name
from .base import FortiGateTool


class VpnTools(FortiGateTool):
    """IPsec tunnel and SSL-VPN session status."""

    def list_ipsec_tunnels(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List IPsec tunnels with phase-2 status, gateway and traffic counters."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            tunnels = api_client.get_ipsec_tunnels(vdom=vdom)
            return self._format_response(tunnels, "ipsec_tunnels")
        except Exception as e:
            return self._handle_error("list ipsec tunnels", device_id, e)

    def list_ssl_vpn_sessions(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List active SSL-VPN sessions."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            sessions = api_client.get_ssl_vpn_sessions(vdom=vdom)
            return self._format_response(sessions, "ssl_vpn_sessions")
        except Exception as e:
            return self._handle_error("list ssl vpn sessions", device_id, e)

    def execute_ipsec_tunnel_action(self, device_id: str, phase1_name: str, action: str,
                                    phase2_name: Optional[str] = None, vdom: Optional[str] = None) -> List[Content]:
        """Bring an IPsec tunnel up or down (monitor/vpn/ipsec/tunnel_up | tunnel_down)."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(phase1_name=phase1_name, action=action)
            if action not in ("up", "down"):
                raise ValueError("action must be 'up' or 'down'")
            payload: Dict[str, Any] = {"p1name": validate_object_name(phase1_name, "phase1_name")}
            if phase2_name:
                payload["p2name"] = validate_object_name(phase2_name, "phase2_name")
            api_client = self._get_device_api(device_id)
            api_client.monitor_post(f"vpn/ipsec/tunnel_{action}", data=payload, vdom=vdom)
            target = phase1_name + (f"/{phase2_name}" if phase2_name else "")
            return self._format_operation_result(f"ipsec tunnel {action}", device_id, True, f"Tunnel {target} brought {action}")
        except Exception as e:
            return self._handle_error(f"ipsec tunnel {action}", device_id, e)

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for VPN tools."""
        return {
            "name": "vpn_tools",
            "description": "FortiGate VPN monitoring tools",
            "operations": [
                {"name": "list_ipsec_tunnels", "description": "List IPsec tunnel status",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "vdom", "type": "string", "required": False}]},
                {"name": "list_ssl_vpn_sessions", "description": "List SSL-VPN sessions",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "vdom", "type": "string", "required": False}]},
            ],
        }
