"""User and identity tools for FortiGate MCP (read-only)."""
from typing import Any, Dict, List, Optional

from mcp.types import TextContent as Content

from .base import FortiGateTool


class UserTools(FortiGateTool):
    """Local users, user groups and authenticated firewall sessions."""

    def list_local_users(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List local user accounts (passwords are never returned by FortiOS)."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            users = api_client.get_local_users(vdom=vdom)
            return self._format_response(users, "local_users")
        except Exception as e:
            return self._handle_error("list local users", device_id, e)

    def list_user_groups(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List user groups and their members."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            groups = api_client.get_user_groups(vdom=vdom)
            return self._format_response(groups, "user_groups")
        except Exception as e:
            return self._handle_error("list user groups", device_id, e)

    def list_firewall_auth_sessions(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List users currently authenticated against identity-based policies."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            sessions = api_client.get_firewall_auth_users(vdom=vdom)
            return self._format_response(sessions, "auth_sessions")
        except Exception as e:
            return self._handle_error("list firewall auth sessions", device_id, e)

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for user tools."""
        return {
            "name": "user_tools",
            "description": "FortiGate user and identity tools",
            "operations": [
                {"name": "list_local_users", "description": "List local users",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "vdom", "type": "string", "required": False}]},
                {"name": "list_user_groups", "description": "List user groups",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "vdom", "type": "string", "required": False}]},
                {"name": "list_firewall_auth_sessions", "description": "List authenticated firewall users",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "vdom", "type": "string", "required": False}]},
            ],
        }
