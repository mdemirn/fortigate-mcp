"""Security profile (UTM) read-only tools for FortiGate MCP."""
from typing import Any, Dict, List, Optional

from mcp.types import TextContent as Content

from .base import FortiGateTool

PROFILE_TYPES = ("application", "webfilter", "antivirus", "ips", "dnsfilter", "ssl-ssh",
                 "dlp", "emailfilter", "file-filter", "icap", "ssh-filter", "waf", "voip", "virtual-patch")
_MAX_APP_NAME_LOOKUPS = 80


class SecurityProfileTools(FortiGateTool):
    """Read-only access to application control, web filter, AV, IPS, DNS filter and SSL profiles."""

    def list_security_profiles(self, device_id: str, profile_type: str,
                               vdom: Optional[str] = None) -> List[Content]:
        """List profiles of one type with a one-line summary each."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(profile_type=profile_type)
            if profile_type not in PROFILE_TYPES:
                raise ValueError("profile_type must be one of: " + ", ".join(PROFILE_TYPES))
            api_client = self._get_device_api(device_id)
            profiles = api_client.get_security_profiles(profile_type, vdom=vdom)
            return self._format_response(profiles, "security_profiles", profile_type=profile_type)
        except Exception as e:
            return self._handle_error("list security profiles", device_id, e)

    def get_security_profile_detail(self, device_id: str, profile_type: str, name: str,
                                    vdom: Optional[str] = None) -> List[Content]:
        """Show one profile in depth (application entries are resolved to signature names)."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(profile_type=profile_type, name=name)
            if profile_type not in PROFILE_TYPES:
                raise ValueError("profile_type must be one of: " + ", ".join(PROFILE_TYPES))
            api_client = self._get_device_api(device_id)
            data = api_client.get_security_profile(profile_type, name, vdom=vdom)
            results = data.get("results")
            profile: Optional[Dict[str, Any]] = None
            if isinstance(results, list) and results:
                profile = results[0]
            elif isinstance(results, dict):
                profile = results
            if not profile:
                raise ValueError(f"Profile not found: {self._safe_id(name)}")
            app_names: Dict[int, Dict[str, Any]] = {}
            if profile_type == "application":
                app_names = self._resolve_application_names(api_client, profile, vdom)
            return self._format_response(profile, "security_profile_detail",
                                         profile_type=profile_type, app_names=app_names)
        except Exception as e:
            return self._handle_error("get security profile detail", device_id, e)

    @staticmethod
    def _resolve_application_names(api_client: Any, profile: Dict[str, Any],
                                   vdom: Optional[str]) -> Dict[int, Dict[str, Any]]:
        """Best-effort lookup of application signature IDs referenced by the profile entries."""
        ids: List[int] = []
        for entry in profile.get("entries", []) or []:
            for app in entry.get("application", []) or []:
                if isinstance(app, dict) and app.get("id") is not None:
                    try:
                        ids.append(int(app["id"]))
                    except (TypeError, ValueError):
                        continue
        ids = sorted(set(ids))[:_MAX_APP_NAME_LOOKUPS]
        if not ids:
            return {}
        try:
            data = api_client.get_application_names(ids, vdom=vdom)
        except Exception:
            return {}
        resolved: Dict[int, Dict[str, Any]] = {}
        for item in data.get("results", []) or []:
            if isinstance(item, dict) and item.get("id") is not None:
                resolved[int(item["id"])] = item
        return resolved

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for security profile tools."""
        return {
            "name": "security_profile_tools",
            "description": "FortiGate security profile (UTM) read-only tools",
            "operations": [
                {"name": "list_security_profiles", "description": "List security profiles of one type",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "profile_type", "type": "string", "required": True},
                                {"name": "vdom", "type": "string", "required": False}]},
                {"name": "get_security_profile_detail", "description": "Get one security profile in detail",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "profile_type", "type": "string", "required": True},
                                {"name": "name", "type": "string", "required": True},
                                {"name": "vdom", "type": "string", "required": False}]},
            ],
        }
