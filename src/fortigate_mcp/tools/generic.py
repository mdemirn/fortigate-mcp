"""Generic pass-through tools: reach any FortiOS cmdb / monitor / log endpoint.

These are the escape hatch for the parts of the REST API that have no typed
tool. Paths and keys are validated before they become URL segments, secret
fields are redacted from every response, and responses are truncated to a
bounded size so a 5,000-row table cannot flood the client.
"""
import json
from typing import Any, Dict, List, Optional

from mcp.types import TextContent as Content

from ..validation import redact_sensitive_fields
from .base import FortiGateTool

MAX_OUTPUT_CHARS = 60_000
_MAX_ROWS = 500


class GenericTools(FortiGateTool):
    """Raw access to cmdb (configuration), monitor (status/actions) and log endpoints."""

    @staticmethod
    def _json_content(data: Any, title: str) -> List[Content]:
        safe = redact_sensitive_fields(data)
        text = json.dumps(safe, indent=2, ensure_ascii=False)
        if len(text) > MAX_OUTPUT_CHARS:
            text = text[:MAX_OUTPUT_CHARS] + f"\n... [truncated at {MAX_OUTPUT_CHARS} characters; narrow with filter/count/format]"
        return [Content(type="text", text=f"{title}\n\n{text}")]

    @staticmethod
    def _list_params(filter_expr: Optional[str], start: Optional[int], count: Optional[int],
                     format_fields: Optional[str]) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if filter_expr:
            # FortiOS accepts several filters as repeated "filter=" params (AND).
            params["filter"] = [f for f in filter_expr.split("&") if f]
        if start is not None:
            params["start"] = int(start)
        if count is not None:
            params["count"] = max(1, int(count))
        if format_fields:
            params["format"] = format_fields
        return params

    def cmdb_list(self, device_id: str, path: str, filter_expr: Optional[str] = None,
                  start: Optional[int] = None, count: Optional[int] = None,
                  format_fields: Optional[str] = None, vdom: Optional[str] = None) -> List[Content]:
        """GET cmdb/{path}: list every object of a configuration table."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(path=path)
            api_client = self._get_device_api(device_id)
            data = api_client.cmdb_list(path, params=self._list_params(filter_expr, start, count, format_fields), vdom=vdom)
            return self._json_content(data, f"cmdb/{path}")
        except Exception as e:
            return self._handle_error("cmdb list", device_id, e)

    def cmdb_get(self, device_id: str, path: str, key: str, vdom: Optional[str] = None) -> List[Content]:
        """GET cmdb/{path}/{key}: one configuration object."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(path=path, key=key)
            api_client = self._get_device_api(device_id)
            data = api_client.cmdb_get(path, key, vdom=vdom)
            return self._json_content(data, f"cmdb/{path}/{key}")
        except Exception as e:
            return self._handle_error("cmdb get", device_id, e)

    def create_cmdb_object(self, device_id: str, path: str, data: Dict[str, Any],
                           vdom: Optional[str] = None) -> List[Content]:
        """POST cmdb/{path}: create a configuration object from a raw payload."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(path=path, data=data)
            api_client = self._get_device_api(device_id)
            result = api_client.cmdb_create(path, data, vdom=vdom)
            mkey = result.get("mkey") if isinstance(result, dict) else None
            return self._format_operation_result("create cmdb object", device_id, True,
                                                 f"Created object in cmdb/{path}" + (f" (key {mkey})" if mkey is not None else ""))
        except Exception as e:
            return self._handle_error("create cmdb object", device_id, e)

    def update_cmdb_object(self, device_id: str, path: str, key: str, data: Dict[str, Any],
                           vdom: Optional[str] = None) -> List[Content]:
        """PUT cmdb/{path}/{key}: change fields of an existing object."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(path=path, key=key, data=data)
            api_client = self._get_device_api(device_id)
            api_client.cmdb_update(path, key, data, vdom=vdom)
            return self._format_operation_result("update cmdb object", device_id, True, f"Updated cmdb/{path}/{key}")
        except Exception as e:
            return self._handle_error("update cmdb object", device_id, e)

    def delete_cmdb_object(self, device_id: str, path: str, key: str, vdom: Optional[str] = None) -> List[Content]:
        """DELETE cmdb/{path}/{key}."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(path=path, key=key)
            api_client = self._get_device_api(device_id)
            api_client.cmdb_delete(path, key, vdom=vdom)
            return self._format_operation_result("delete cmdb object", device_id, True, f"Deleted cmdb/{path}/{key}")
        except Exception as e:
            return self._handle_error("delete cmdb object", device_id, e)

    def monitor_get(self, device_id: str, path: str, params: Optional[Dict[str, Any]] = None,
                    vdom: Optional[str] = None) -> List[Content]:
        """GET monitor/{path}: live status data (sessions, routes, licenses, ...)."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(path=path)
            api_client = self._get_device_api(device_id)
            data = api_client.monitor_get(path, params=params or None, vdom=vdom)
            return self._json_content(data, f"monitor/{path}")
        except Exception as e:
            return self._handle_error("monitor get", device_id, e)

    def execute_monitor_action(self, device_id: str, path: str, data: Optional[Dict[str, Any]] = None,
                               vdom: Optional[str] = None) -> List[Content]:
        """POST monitor/{path}: run an action (tunnel up/down, session close, ...)."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(path=path)
            api_client = self._get_device_api(device_id)
            result = api_client.monitor_post(path, data=data, vdom=vdom)
            return self._json_content(result, f"monitor/{path} (POST)")
        except Exception as e:
            return self._handle_error("execute monitor action", device_id, e)

    def log_get(self, device_id: str, path: str, rows: int = 50, filter_expr: Optional[str] = None,
                vdom: Optional[str] = None) -> List[Content]:
        """GET log/{path}: raw log records (e.g. memory/event/system, disk/traffic/forward)."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(path=path)
            filters = [f for f in (filter_expr or "").split("&") if f]
            api_client = self._get_device_api(device_id)
            data = api_client.log_get(path, rows=max(1, min(int(rows), _MAX_ROWS)), filters=filters, vdom=vdom)
            return self._json_content(data, f"log/{path}")
        except Exception as e:
            return self._handle_error("log get", device_id, e)

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for generic tools."""
        return {
            "name": "generic_tools",
            "description": "Generic FortiOS cmdb/monitor/log pass-through tools",
            "operations": [
                {"name": "cmdb_list", "description": "GET cmdb/{path}", "parameters": [
                    {"name": "device_id", "type": "string", "required": True}, {"name": "path", "type": "string", "required": True},
                    {"name": "filter_expr", "type": "string", "required": False}, {"name": "start", "type": "integer", "required": False},
                    {"name": "count", "type": "integer", "required": False}, {"name": "format_fields", "type": "string", "required": False},
                    {"name": "vdom", "type": "string", "required": False}]},
                {"name": "cmdb_get", "description": "GET cmdb/{path}/{key}", "parameters": [
                    {"name": "device_id", "type": "string", "required": True}, {"name": "path", "type": "string", "required": True},
                    {"name": "key", "type": "string", "required": True}, {"name": "vdom", "type": "string", "required": False}]},
                {"name": "create_cmdb_object", "description": "POST cmdb/{path}", "parameters": [
                    {"name": "device_id", "type": "string", "required": True}, {"name": "path", "type": "string", "required": True},
                    {"name": "data", "type": "object", "required": True}, {"name": "vdom", "type": "string", "required": False}]},
                {"name": "update_cmdb_object", "description": "PUT cmdb/{path}/{key}", "parameters": [
                    {"name": "device_id", "type": "string", "required": True}, {"name": "path", "type": "string", "required": True},
                    {"name": "key", "type": "string", "required": True}, {"name": "data", "type": "object", "required": True},
                    {"name": "vdom", "type": "string", "required": False}]},
                {"name": "delete_cmdb_object", "description": "DELETE cmdb/{path}/{key}", "parameters": [
                    {"name": "device_id", "type": "string", "required": True}, {"name": "path", "type": "string", "required": True},
                    {"name": "key", "type": "string", "required": True}, {"name": "vdom", "type": "string", "required": False}]},
                {"name": "monitor_get", "description": "GET monitor/{path}", "parameters": [
                    {"name": "device_id", "type": "string", "required": True}, {"name": "path", "type": "string", "required": True},
                    {"name": "params", "type": "object", "required": False}, {"name": "vdom", "type": "string", "required": False}]},
                {"name": "execute_monitor_action", "description": "POST monitor/{path}", "parameters": [
                    {"name": "device_id", "type": "string", "required": True}, {"name": "path", "type": "string", "required": True},
                    {"name": "data", "type": "object", "required": False}, {"name": "vdom", "type": "string", "required": False}]},
                {"name": "log_get", "description": "GET log/{path}", "parameters": [
                    {"name": "device_id", "type": "string", "required": True}, {"name": "path", "type": "string", "required": True},
                    {"name": "rows", "type": "integer", "required": False}, {"name": "filter_expr", "type": "string", "required": False},
                    {"name": "vdom", "type": "string", "required": False}]},
            ],
        }
