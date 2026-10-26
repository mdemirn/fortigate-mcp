"""Firewall policy management tools for FortiGate MCP."""
import ipaddress
from typing import Dict, Any, List, Optional
from mcp.types import TextContent as Content
from ..validation import validate_interface_name
from .base import FortiGateTool


def protocol_text_upper(proto_text: str) -> str:
    return proto_text.upper() if not proto_text.isdigit() else f"proto {proto_text}"

class FirewallTools(FortiGateTool):
    """Tools for FortiGate firewall policy management."""
    
    def list_policies(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List firewall policies."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            policies_data = api_client.get_firewall_policies(vdom=vdom)
            return self._format_response(policies_data, "firewall_policies")
        except Exception as e:
            return self._handle_error("list firewall policies", device_id, e)
    
    def create_policy(self, device_id: str, policy_data: Dict[str, Any], 
                     vdom: Optional[str] = None) -> List[Content]:
        """Create firewall policy."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_data=policy_data)
            
            api_client = self._get_device_api(device_id)
            api_client.create_firewall_policy(policy_data, vdom=vdom)
            return self._format_operation_result("create firewall policy", device_id, True, "Policy created successfully")
        except Exception as e:
            return self._handle_error("create firewall policy", device_id, e)
    
    def update_policy(self, device_id: str, policy_id: str, 
                     policy_data: Dict[str, Any], vdom: Optional[str] = None) -> List[Content]:
        """Update firewall policy."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id, policy_data=policy_data)
            
            api_client = self._get_device_api(device_id)
            api_client.update_firewall_policy(policy_id, policy_data, vdom=vdom)
            return self._format_operation_result("update firewall policy", device_id, True, f"Policy {policy_id} updated successfully")
        except Exception as e:
            return self._handle_error("update firewall policy", device_id, e)
    
    def get_policy_detail(self, device_id: str, policy_id: str, 
                         vdom: Optional[str] = None) -> List[Content]:
        """Get detailed information for a specific firewall policy."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id)
            
            api_client = self._get_device_api(device_id)
            
            # Get policy details
            policy_data = api_client.get_firewall_policy_detail(policy_id, vdom=vdom)
            
            # Get address/service objects and groups for resolution
            address_objects, service_objects, address_groups, service_groups = \
                self._fetch_resolution_data(api_client, vdom)
            
            return self._format_response(
                policy_data, 
                "firewall_policy_detail", 
                device_id=device_id,
                address_objects=address_objects,
                service_objects=service_objects,
                address_groups=address_groups,
                service_groups=service_groups
            )
        except Exception as e:
            return self._handle_error("get firewall policy detail", device_id, e)
    
    @staticmethod
    def _fetch_resolution_data(api_client: Any, vdom: Optional[str]) -> Any:
        """Best-effort fetch of the lookup tables used to resolve policy members.

        Each table is optional: a failure (e.g. an API profile without
        permission on groups) degrades that table to None instead of failing
        the whole policy-detail call.
        """
        tables = []
        for getter in (api_client.get_address_objects, api_client.get_service_objects,
                       api_client.get_address_groups, api_client.get_service_groups):
            try:
                tables.append(getter(vdom=vdom))
            except Exception:
                tables.append(None)
        return tuple(tables)

    def move_policy(self, device_id: str, policy_id: str, position: str, reference_id: str,
                    vdom: Optional[str] = None) -> List[Content]:
        """Move a policy before or after another policy (evaluation order)."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id, position=position, reference_id=reference_id)
            if str(policy_id) == str(reference_id):
                raise ValueError("policy_id and reference_id must differ")
            api_client = self._get_device_api(device_id)
            api_client.move_firewall_policy(policy_id, position, reference_id, vdom=vdom)
            return self._format_operation_result("move firewall policy", device_id, True,
                                                 f"Policy {policy_id} moved {position} policy {reference_id}")
        except Exception as e:
            return self._handle_error("move firewall policy", device_id, e)

    def lookup_policy(self, device_id: str, source_ip: str, destination_ip: str, destination_port: int,
                      protocol: str = "tcp", source_interface: Optional[str] = None,
                      source_port: Optional[int] = None, vdom: Optional[str] = None) -> List[Content]:
        """Ask the device which policy a hypothetical flow would match (monitor/firewall/policy-lookup)."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(source_ip=source_ip, destination_ip=destination_ip)
            ipaddress.ip_address(source_ip)
            ipaddress.ip_address(destination_ip)
            proto_map = {"tcp": 6, "udp": 17, "icmp": 1, "sctp": 132}
            proto_text = str(protocol).lower()
            if proto_text in proto_map:
                protocol_number = proto_map[proto_text]
            elif proto_text.isdigit():
                protocol_number = int(proto_text)
            else:
                raise ValueError("protocol must be tcp, udp, icmp, sctp or a protocol number")
            params: Dict[str, Any] = {
                "sourceip": source_ip, "dest": destination_ip, "destport": int(destination_port),
                "protocol": protocol_number, "ipv6": False,
            }
            if source_interface:
                params["srcintf"] = validate_interface_name(source_interface)
            if source_port is not None:
                params["sourceport"] = int(source_port)
            api_client = self._get_device_api(device_id)
            result = api_client.monitor_get("firewall/policy-lookup", params=params, vdom=vdom)
            body = result.get("results", result)
            lines = [f"Policy Lookup - Device: {device_id}", "",
                     f"  Flow: {protocol_text_upper(proto_text)} {source_ip}" + (f":{source_port}" if source_port is not None else "")
                     + f" -> {destination_ip}:{destination_port}" + (f" via {source_interface}" if source_interface else ""), ""]
            if isinstance(body, dict):
                if body.get("success") is False or body.get("policy_id") in (None, 0) and not body.get("policy_name"):
                    lines.append("  Result: no matching policy (implicit deny) or lookup unsupported")
                for key in ("policy_id", "policy_name", "action", "policy_type", "srcintf", "dstintf", "nat", "log", "utm_status"):
                    if body.get(key) not in (None, ""):
                        lines.append(f"  {key}: {body[key]}")
                extra = {k: v for k, v in body.items() if k not in ("policy_id", "policy_name", "action", "policy_type", "srcintf", "dstintf", "nat", "log", "utm_status")}
                if extra:
                    lines.append("  details: " + ", ".join(f"{k}={v}" for k, v in extra.items() if isinstance(v, (str, int, float, bool)))[:600])
            else:
                lines.append(f"  Result: {body}")
            return [Content(type="text", text="\n".join(lines))]
        except Exception as e:
            return self._handle_error("lookup policy", device_id, e)

    def delete_policy(self, device_id: str, policy_id: str, 
                     vdom: Optional[str] = None) -> List[Content]:
        """Delete firewall policy."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id)
            
            api_client = self._get_device_api(device_id)
            api_client.delete_firewall_policy(policy_id, vdom=vdom)
            return self._format_operation_result("delete firewall policy", device_id, True, f"Policy {policy_id} deleted successfully")
        except Exception as e:
            return self._handle_error("delete firewall policy", device_id, e)
    
    async def get_policy_detail_async(self, device_id: str, policy_id: str, 
                                     vdom: Optional[str] = None) -> List[Content]:
        """Get detailed information for a specific firewall policy (async version)."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id)
            
            api_client = self._get_device_api(device_id)
            
            # Get policy details
            policy_data = api_client.get_firewall_policy_detail(policy_id, vdom=vdom)
            
            # Get address/service objects and groups for resolution
            address_objects, service_objects, address_groups, service_groups = \
                self._fetch_resolution_data(api_client, vdom)
            
            return self._format_response(
                policy_data, 
                "firewall_policy_detail", 
                device_id=device_id,
                address_objects=address_objects,
                service_objects=service_objects,
                address_groups=address_groups,
                service_groups=service_groups
            )
        except Exception as e:
            return self._handle_error("get firewall policy detail", device_id, e)
    
    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for firewall tools.
        
        Returns:
            Dictionary with schema information
        """
        return {
            "name": "firewall_tools",
            "description": "FortiGate firewall policy management tools",
            "operations": [
                {
                    "name": "list_policies",
                    "description": "List firewall policies",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "create_policy",
                    "description": "Create firewall policy",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "policy_data", "type": "object", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "update_policy",
                    "description": "Update firewall policy",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "policy_id", "type": "string", "required": True},
                        {"name": "policy_data", "type": "object", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "get_policy_detail",
                    "description": "Get detailed information for a specific firewall policy",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "policy_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "delete_policy",
                    "description": "Delete firewall policy",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "policy_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "move_policy",
                    "description": "Move firewall policy before/after another policy",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "policy_id", "type": "string", "required": True},
                        {"name": "position", "type": "string", "required": True},
                        {"name": "reference_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                }
            ]
        }
