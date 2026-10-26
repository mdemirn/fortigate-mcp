"""System monitoring, session table, traffic log and config backup tools for FortiGate MCP."""
import os
import re
from typing import Any, Dict, List, Optional

from mcp.types import TextContent as Content

from ..formatting.templates import FortiGateTemplates
from .base import FortiGateTool

# Values interpolated into FortiOS filter expressions (sent as query parameters,
# so they are URL-encoded by httpx) -- still restricted to a conservative charset.
_FILTER_VALUE_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,64}$")
_RAW_FILTER_RE = re.compile(r"^[A-Za-z0-9_.:/=!<>~*,@ -]{1,200}$")
_MAX_ROWS = 500


def _filter_value(value: Any, field_name: str) -> str:
    text = str(value).strip()
    if not _FILTER_VALUE_RE.match(text):
        raise ValueError(f"{field_name} contains unsupported characters")
    return text


class SystemTools(FortiGateTool):
    """Resource usage, live sessions, traffic log queries and configuration backup."""

    def get_system_resources(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """Show CPU, memory, disk and session counters."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            usage = api_client.get_resource_usage(vdom=vdom)
            return self._format_response(usage, "resource_usage")
        except Exception as e:
            return self._handle_error("get system resources", device_id, e)

    def list_active_sessions(self, device_id: str, source_ip: Optional[str] = None,
                             destination_ip: Optional[str] = None, destination_port: Optional[int] = None,
                             policy_id: Optional[str] = None, count: int = 50,
                             vdom: Optional[str] = None) -> List[Content]:
        """Query the live session table with optional filters."""
        try:
            self._validate_device_exists(device_id)
            filters: List[str] = []
            if source_ip:
                filters.append(f"srcaddr=={_filter_value(source_ip, 'source_ip')}")
            if destination_ip:
                filters.append(f"dstaddr=={_filter_value(destination_ip, 'destination_ip')}")
            if destination_port is not None:
                filters.append(f"dstport=={int(destination_port)}")
            if policy_id:
                filters.append(f"policyid=={int(str(policy_id))}")
            api_client = self._get_device_api(device_id)
            sessions = api_client.get_sessions(filters=filters, count=max(1, min(int(count), _MAX_ROWS)), vdom=vdom)
            return self._format_response(sessions, "sessions")
        except Exception as e:
            return self._handle_error("list active sessions", device_id, e)

    def query_traffic_log(self, device_id: str, source_ip: Optional[str] = None,
                          destination_ip: Optional[str] = None, destination_port: Optional[int] = None,
                          policy_id: Optional[str] = None, action: Optional[str] = None,
                          rows: int = 50, source: str = "memory", raw_filter: Optional[str] = None,
                          vdom: Optional[str] = None) -> List[Content]:
        """Query forward traffic logs (memory by default; 'disk' on models with log disks)."""
        try:
            self._validate_device_exists(device_id)
            filters: List[str] = []
            if source_ip:
                filters.append(f"srcip=={_filter_value(source_ip, 'source_ip')}")
            if destination_ip:
                filters.append(f"dstip=={_filter_value(destination_ip, 'destination_ip')}")
            if destination_port is not None:
                filters.append(f"dstport=={int(destination_port)}")
            if policy_id:
                filters.append(f"policyid=={int(str(policy_id))}")
            if action:
                filters.append(f"action=={_filter_value(action, 'action')}")
            if raw_filter:
                if not _RAW_FILTER_RE.match(raw_filter):
                    raise ValueError("raw_filter contains unsupported characters")
                filters.append(raw_filter)
            api_client = self._get_device_api(device_id)
            logs = api_client.get_traffic_logs(source=source, rows=max(1, min(int(rows), _MAX_ROWS)),
                                               filters=filters, vdom=vdom)
            return self._format_response(logs, "traffic_log")
        except Exception as e:
            return self._handle_error("query traffic log", device_id, e)

    def backup_config(self, device_id: str, output_path: str, scope: str = "global",
                      overwrite: bool = False, vdom: Optional[str] = None) -> List[Content]:
        """Download the running configuration and save it to a local file.

        The file is written on the machine running this MCP server. An existing
        file is never overwritten unless ``overwrite`` is true.
        """
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(output_path=output_path)
            path = os.path.abspath(os.path.expanduser(output_path))
            if os.path.isdir(path):
                raise ValueError("output_path is a directory; give a file path")
            if os.path.exists(path) and not overwrite:
                raise ValueError("output_path already exists; pass overwrite=true to replace it")
            parent = os.path.dirname(path)
            if not os.path.isdir(parent):
                raise ValueError("output_path parent directory does not exist")
            api_client = self._get_device_api(device_id)
            result = api_client.backup_config(scope=scope, vdom=vdom)
            text = result.get("text", "")
            if not isinstance(text, str) or "config " not in text:
                raise ValueError("Device did not return a configuration body (check API profile permissions)")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)
            line_count = text.count("\n")
            return self._format_operation_result(
                "backup config", device_id, True,
                f"Configuration saved to {path} ({len(text.encode('utf-8'))} bytes, {line_count} lines, scope={scope})",
            )
        except Exception as e:
            return self._handle_error("backup config", device_id, e)

    FORTIVIEW_REPORTS = {
        "source": "source", "destination": "destination", "application": "application",
        "threat": "threat", "country": "country", "policy": "policy", "interface": "interface",
        "website": "website", "web_category": "web-category",
    }

    def get_fortiview_top(self, device_id: str, report_by: str = "source", count: int = 20,
                          sort_by: str = "bytes", source_interface: Optional[str] = None,
                          vdom: Optional[str] = None) -> List[Content]:
        """FortiView top talkers from the real-time session statistics (monitor/fortiview/statistics)."""
        try:
            self._validate_device_exists(device_id)
            if report_by not in self.FORTIVIEW_REPORTS:
                raise ValueError("report_by must be one of: " + ", ".join(self.FORTIVIEW_REPORTS))
            if sort_by not in ("bytes", "sessions", "bandwidth"):
                raise ValueError("sort_by must be bytes, sessions or bandwidth")
            params: Dict[str, Any] = {
                "report_by": self.FORTIVIEW_REPORTS[report_by], "count": max(1, min(int(count), 200)),
                "sort_by": sort_by, "realtime": True, "ip_version": "ipv4",
            }
            if source_interface:
                params["filter"] = {"srcintf": [source_interface]}
            api_client = self._get_device_api(device_id)
            result = api_client.monitor_get("fortiview/statistics", params=params, vdom=vdom)
            body = result.get("results", result)
            rows = body.get("details", body) if isinstance(body, dict) else body
            rows = [r for r in (rows or []) if isinstance(r, dict)]
            lines = [f"FortiView Top {report_by} (by {sort_by}, {len(rows)} rows)", ""]
            if not rows:
                lines.append("No data (FortiView realtime statistics may be unavailable on this model)")
            for r in rows:
                label = r.get("srcip") or r.get("dstip") or r.get("application") or r.get("threat") or r.get("country") or r.get("policyid") or r.get("srcintf") or r.get("website") or r.get("web_category") or "?"
                name = f" ({r['srcname']})" if r.get("srcname") else ""
                lines.append(f"  {str(label):32s}{name}  sessions {r.get('sessions', '?')}  bytes {FortiGateTemplates._fmt_bytes(r.get('bytes', 0))}  bandwidth {r.get('bandwidth', '?')}")
            return [Content(type="text", text="\n".join(lines))]
        except Exception as e:
            return self._handle_error("get fortiview top", device_id, e)

    def ping_from_device(self, device_id: str, target: str, source_interface: Optional[str] = None,
                         vdom: Optional[str] = None) -> List[Content]:
        """Ping a host from the FortiGate itself (monitor/network/diag-icmp-ping)."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(target=target)
            params: Dict[str, Any] = {"target": _filter_value(target, "target")}
            if source_interface:
                params["srcintf"] = source_interface
            api_client = self._get_device_api(device_id)
            result = api_client.monitor_get("network/diag-icmp-ping", params=params, vdom=vdom)
            body = result.get("results", result)
            lines = [f"Ping from {device_id} to {target}", ""]
            if isinstance(body, dict):
                for key, value in body.items():
                    if isinstance(value, (str, int, float, bool)):
                        lines.append(f"  {key}: {value}")
            else:
                lines.append(f"  {body}")
            return [Content(type="text", text="\n".join(lines))]
        except Exception as e:
            return self._handle_error("ping from device", device_id, e)

    def geoip_lookup(self, device_id: str, ip: str, vdom: Optional[str] = None) -> List[Content]:
        """Resolve an IP to its FortiGuard geolocation (monitor/geoip/geoip-query)."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(ip=ip)
            safe_ip = _filter_value(ip, "ip")
            api_client = self._get_device_api(device_id)
            result = api_client.monitor_post("geoip/geoip-query/select", data={"ip_addresses": [safe_ip]}, vdom=vdom)
            body = result.get("results", result)
            lines = [f"GeoIP lookup: {safe_ip}", ""]
            rows = body if isinstance(body, list) else [body]
            for r in rows:
                if isinstance(r, dict):
                    lines.append("  " + ", ".join(f"{k}={v}" for k, v in r.items() if isinstance(v, (str, int, float))))
            return [Content(type="text", text="\n".join(lines))]
        except Exception as e:
            return self._handle_error("geoip lookup", device_id, e)

    EVENT_CATEGORIES = ("system", "vpn", "user", "router", "wireless", "endpoint", "ha", "security-rating", "fortiextender", "connector", "sdwan", "cifs", "compliance-check")
    UTM_TYPES = ("virus", "webfilter", "ips", "app-ctrl", "dns", "emailfilter", "dlp", "ssl", "anomaly", "waf", "file-filter", "ssh", "voip", "icap", "virtual-patch")

    def query_event_log(self, device_id: str, category: str = "system", rows: int = 50,
                        raw_filter: Optional[str] = None, source: str = "memory",
                        vdom: Optional[str] = None) -> List[Content]:
        """Query event logs (system, vpn, user, router, wireless, ...)."""
        try:
            self._validate_device_exists(device_id)
            if category not in self.EVENT_CATEGORIES:
                raise ValueError("category must be one of: " + ", ".join(self.EVENT_CATEGORIES))
            if source not in ("memory", "disk"):
                raise ValueError("source must be 'memory' or 'disk'")
            filters: List[str] = []
            if raw_filter:
                if not _RAW_FILTER_RE.match(raw_filter):
                    raise ValueError("raw_filter contains unsupported characters")
                filters.append(raw_filter)
            api_client = self._get_device_api(device_id)
            logs = api_client.log_get(f"{source}/event/{category}", rows=max(1, min(int(rows), _MAX_ROWS)), filters=filters, vdom=vdom)
            return self._format_response(logs, "event_log", category=category)
        except Exception as e:
            return self._handle_error("query event log", device_id, e)

    def query_utm_log(self, device_id: str, log_type: str = "webfilter", rows: int = 50,
                      source_ip: Optional[str] = None, raw_filter: Optional[str] = None,
                      source: str = "memory", vdom: Optional[str] = None) -> List[Content]:
        """Query UTM logs (virus, webfilter, ips, app-ctrl, dns, ...)."""
        try:
            self._validate_device_exists(device_id)
            if log_type not in self.UTM_TYPES:
                raise ValueError("log_type must be one of: " + ", ".join(self.UTM_TYPES))
            if source not in ("memory", "disk"):
                raise ValueError("source must be 'memory' or 'disk'")
            filters: List[str] = []
            if source_ip:
                filters.append(f"srcip=={_filter_value(source_ip, 'source_ip')}")
            if raw_filter:
                if not _RAW_FILTER_RE.match(raw_filter):
                    raise ValueError("raw_filter contains unsupported characters")
                filters.append(raw_filter)
            api_client = self._get_device_api(device_id)
            logs = api_client.log_get(f"{source}/utm/{log_type}", rows=max(1, min(int(rows), _MAX_ROWS)), filters=filters, vdom=vdom)
            return self._format_response(logs, "utm_log", log_type=log_type)
        except Exception as e:
            return self._handle_error("query utm log", device_id, e)

    def get_log_settings(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """Show where logs go: memory, disk, syslog and FortiAnalyzer settings."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            lines = [f"Log Settings - Device: {device_id}", ""]
            for label, path in (("Memory", "log.memory/setting"), ("Disk", "log.disk/setting"),
                                ("Syslog", "log.syslogd/setting"), ("FortiAnalyzer", "log.fortianalyzer/setting"),
                                ("FortiCloud", "log.fortiguard/setting")):
                try:
                    data = api_client.cmdb_list(path, vdom=vdom)
                    body = data.get("results", data)
                    body = body[0] if isinstance(body, list) and body else body
                    if not isinstance(body, dict):
                        lines.append(f"{label}: (no data)")
                        continue
                    keys = [k for k in ("status", "server", "port", "mode", "upload-option", "reliable", "enc-algorithm", "max-size", "full-first-warning-threshold", "diskfull", "source-ip", "facility") if body.get(k) not in (None, "")]
                    lines.append(f"{label}: " + ", ".join(f"{k}={body[k]}" for k in keys))
                except Exception as inner:
                    lines.append(f"{label}: unavailable ({str(inner)[:80]})")
            return [Content(type="text", text="\n".join(lines))]
        except Exception as e:
            return self._handle_error("get log settings", device_id, e)

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for system tools."""
        return {
            "name": "system_tools",
            "description": "FortiGate system monitoring, sessions, logs and backup tools",
            "operations": [
                {"name": "get_system_resources", "description": "CPU/memory/session usage",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "vdom", "type": "string", "required": False}]},
                {"name": "list_active_sessions", "description": "Query the live session table",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "source_ip", "type": "string", "required": False},
                                {"name": "destination_ip", "type": "string", "required": False},
                                {"name": "destination_port", "type": "integer", "required": False},
                                {"name": "policy_id", "type": "string", "required": False},
                                {"name": "count", "type": "integer", "required": False},
                                {"name": "vdom", "type": "string", "required": False}]},
                {"name": "query_traffic_log", "description": "Query forward traffic logs",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "source_ip", "type": "string", "required": False},
                                {"name": "destination_ip", "type": "string", "required": False},
                                {"name": "destination_port", "type": "integer", "required": False},
                                {"name": "policy_id", "type": "string", "required": False},
                                {"name": "action", "type": "string", "required": False},
                                {"name": "rows", "type": "integer", "required": False},
                                {"name": "source", "type": "string", "required": False},
                                {"name": "raw_filter", "type": "string", "required": False},
                                {"name": "vdom", "type": "string", "required": False}]},
                {"name": "backup_config", "description": "Save the running configuration to a local file",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "output_path", "type": "string", "required": True},
                                {"name": "scope", "type": "string", "required": False},
                                {"name": "overwrite", "type": "boolean", "required": False},
                                {"name": "vdom", "type": "string", "required": False}]},
            ],
        }
