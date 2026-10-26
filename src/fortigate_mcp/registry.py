"""Shared MCP tool registry for FortiGate MCP (CONS-01).

Both the stdio server (server.py) and the HTTP server (server_http.py)
register tools from this single module instead of each hand-duplicating a
~30-tool ``_setup_tools()`` body. 24 of the 33 unique tool names are
schema-identical and share ONE tool definition; ``get_firewall_policy_detail``
is schema-identical but was dispatch-divergent (sync vs async on the same
class) -- it is unified here to a single async definition, verified safe
because FirewallTools' sync and async policy-detail method bodies are
byte-identical except for the ``async`` keyword. 3 create-tools
(``create_address_object``, ``create_service_object``, ``create_static_route``)
have genuinely divergent parameter schemas (dict payload on stdio vs
individual fields on HTTP) and register transport-marked variants -- this is
a locked CONS-01 decision, not an oversight; unifying their signatures is a
contract change deferred to a post-release milestone. 5 tools are
transport-exclusive (``health_check``/``get_server_info`` stdio-only;
``test_connection``/``health``/``get_schema_info`` HTTP-only).

``register_tools`` never constructs a FastMCP instance -- it only decorates
the ``mcp`` object passed in, so it is duck-typed across whichever engine(s)
stdio and HTTP end up on (``mcp.server.fastmcp.FastMCP`` and/or
``fastmcp.FastMCP``).
"""
import asyncio
import functools
import json
import os
from datetime import datetime
from typing import Annotated, Any, Callable, List, Literal, Optional, cast

from fastmcp.exceptions import ToolError
from pydantic import Field
from mcp.types import TextContent as Content

from .formatting import FortiGateFormatters
from .tools.definitions import (
    LIST_DEVICES_DESC,
    GET_DEVICE_STATUS_DESC,
    TEST_DEVICE_CONNECTION_DESC,
    ADD_DEVICE_DESC,
    REMOVE_DEVICE_DESC,
    DISCOVER_VDOMS_DESC,
    LIST_FIREWALL_POLICIES_DESC,
    CREATE_FIREWALL_POLICY_DESC,
    UPDATE_FIREWALL_POLICY_DESC,
    DELETE_FIREWALL_POLICY_DESC,
    LIST_ADDRESS_OBJECTS_DESC,
    CREATE_ADDRESS_OBJECT_DESC,
    LIST_SERVICE_OBJECTS_DESC,
    CREATE_SERVICE_OBJECT_DESC,
    LIST_VIRTUAL_IPS_DESC,
    CREATE_VIRTUAL_IP_DESC,
    UPDATE_VIRTUAL_IP_DESC,
    GET_VIRTUAL_IP_DETAIL_DESC,
    DELETE_VIRTUAL_IP_DESC,
    UPDATE_STATIC_ROUTE_DESC,
    DELETE_STATIC_ROUTE_DESC,
    GET_STATIC_ROUTE_DETAIL_DESC,
    LIST_STATIC_ROUTES_DESC,
    CREATE_STATIC_ROUTE_DESC,
    GET_ROUTING_TABLE_DESC,
    LIST_INTERFACES_DESC,
    GET_INTERFACE_STATUS_DESC,
    HEALTH_CHECK_DESC,
    GET_SERVER_INFO_DESC,
    LIST_ADDRESS_GROUPS_DESC,
    GET_ADDRESS_GROUP_DETAIL_DESC,
    CREATE_ADDRESS_GROUP_DESC,
    ADD_ADDRESS_GROUP_MEMBERS_DESC,
    REMOVE_ADDRESS_GROUP_MEMBERS_DESC,
    DELETE_ADDRESS_GROUP_DESC,
    UPDATE_ADDRESS_OBJECT_DESC,
    DELETE_ADDRESS_OBJECT_DESC,
    UPDATE_SERVICE_OBJECT_DESC,
    DELETE_SERVICE_OBJECT_DESC,
    LIST_SERVICE_GROUPS_DESC,
    MOVE_FIREWALL_POLICY_DESC,
    LIST_DHCP_SERVERS_DESC,
    LIST_DHCP_LEASES_DESC,
    CREATE_DHCP_RESERVATION_DESC,
    DELETE_DHCP_RESERVATION_DESC,
    LIST_SECURITY_PROFILES_DESC,
    GET_SECURITY_PROFILE_DETAIL_DESC,
    LIST_IPSEC_TUNNELS_DESC,
    LIST_SSL_VPN_SESSIONS_DESC,
    LIST_LOCAL_USERS_DESC,
    LIST_USER_GROUPS_DESC,
    LIST_FIREWALL_AUTH_SESSIONS_DESC,
    GET_SYSTEM_RESOURCES_DESC,
    LIST_ACTIVE_SESSIONS_DESC,
    QUERY_TRAFFIC_LOG_DESC,
    BACKUP_CONFIG_DESC,
    CMDB_LIST_DESC,
    CMDB_GET_DESC,
    CREATE_CMDB_OBJECT_DESC,
    UPDATE_CMDB_OBJECT_DESC,
    DELETE_CMDB_OBJECT_DESC,
    MONITOR_GET_DESC,
    EXECUTE_MONITOR_ACTION_DESC,
    LOG_GET_DESC,
    LOOKUP_POLICY_DESC,
    LOOKUP_ROUTE_DESC,
    EXECUTE_IPSEC_TUNNEL_ACTION_DESC,
    GET_FORTIVIEW_TOP_DESC,
    PING_FROM_DEVICE_DESC,
    GEOIP_LOOKUP_DESC,
    QUERY_EVENT_LOG_DESC,
    QUERY_UTM_LOG_DESC,
    GET_LOG_SETTINGS_DESC,
)
from .tools.catalog import CATALOG


RISK_CLASSIFICATION = {
    # read -- list/get/discover/test/health/schema/server-info, never gated
    "list_devices": "read",
    "get_device_status": "read",
    "test_device_connection": "read",
    "discover_vdoms": "read",
    "list_firewall_policies": "read",
    "get_firewall_policy_detail": "read",
    "list_address_objects": "read",
    "list_service_objects": "read",
    "list_static_routes": "read",
    "get_routing_table": "read",
    "list_interfaces": "read",
    "get_interface_status": "read",
    "get_static_route_detail": "read",
    "list_virtual_ips": "read",
    "get_virtual_ip_detail": "read",
    "health_check": "read",
    "get_server_info": "read",
    "test_connection": "read",
    "health": "read",
    "get_schema_info": "read",
    "list_address_groups": "read",
    "get_address_group_detail": "read",
    "list_service_groups": "read",
    "list_dhcp_servers": "read",
    "list_dhcp_leases": "read",
    "list_security_profiles": "read",
    "get_security_profile_detail": "read",
    "list_ipsec_tunnels": "read",
    "list_ssl_vpn_sessions": "read",
    "list_local_users": "read",
    "list_user_groups": "read",
    "list_firewall_auth_sessions": "read",
    "get_system_resources": "read",
    "list_active_sessions": "read",
    "query_traffic_log": "read",
    "backup_config": "read",
    "cmdb_list": "read",
    "cmdb_get": "read",
    "monitor_get": "read",
    "log_get": "read",
    "lookup_policy": "read",
    "lookup_route": "read",
    "get_fortiview_top": "read",
    "ping_from_device": "read",
    "geoip_lookup": "read",
    "query_event_log": "read",
    "query_utm_log": "read",
    "get_log_settings": "read",
    # write -- create_*/update_*/add_*/move_*
    "add_device": "write",
    "create_firewall_policy": "write",
    "update_firewall_policy": "write",
    "create_address_object": "write",
    "create_service_object": "write",
    "update_static_route": "write",
    "create_static_route": "write",
    "create_virtual_ip": "write",
    "update_virtual_ip": "write",
    "create_address_group": "write",
    "add_address_group_members": "write",
    "update_address_object": "write",
    "update_service_object": "write",
    "move_firewall_policy": "write",
    "create_dhcp_reservation": "write",
    "create_cmdb_object": "write",
    "update_cmdb_object": "write",
    "execute_monitor_action": "write",
    "execute_ipsec_tunnel_action": "write",
    # destructive -- delete_*/remove_*
    "remove_device": "destructive",
    "delete_firewall_policy": "destructive",
    "delete_static_route": "destructive",
    "delete_virtual_ip": "destructive",
    "remove_address_group_members": "destructive",
    "delete_address_group": "destructive",
    "delete_address_object": "destructive",
    "delete_service_object": "destructive",
    "delete_dhcp_reservation": "destructive",
    "delete_cmdb_object": "destructive",
}
# Every catalog entry is a parameterless GET -> read.
RISK_CLASSIFICATION.update({entry.name: "read" for entry in CATALOG})
"""Canonical per-tool risk classification (SEC-02).

Single source of truth for BOTH the dispatch-layer read-only gate (SEC-01,
``_tool()``'s ``_gate`` helper below) and Phase 5's SECURITY.md tool-risk
table. Covers all 60 unique tool names registered across transports;
completeness is enforced by ``tests/test_write_gate.py``. An unclassified
name is a registration-time KeyError (see ``_gate``), not a silent gap.
"""


def _format_json_response(data: Any, operation: str = "operation", logger: Any = None) -> List[Content]:
    """Module-level replacement for server_http.py's ``self._format_response``.

    Used only by the 3 HTTP-only tools (test_connection/health/get_schema_info)
    so the registry's duck-type contract for ``tools`` never requires a
    ``_format_response`` method.
    """
    try:
        if isinstance(data, (dict, list)):
            formatted_data = json.dumps(data, indent=2, ensure_ascii=False)
        else:
            formatted_data = str(data)

        return [Content(type="text", text=formatted_data)]

    except Exception as e:
        if logger is not None:
            logger.error(f"Error formatting response for {operation}: {e}")
        error_response = {
            "error": f"Failed to format response: {str(e)}",
            "operation": operation,
        }
        return [Content(type="text", text=json.dumps(error_response, indent=2))]


def register_tools(mcp: Any, tools: Any, transport: Literal["stdio", "http"]) -> int:
    """Register every FortiGate MCP tool on ``mcp`` for the given ``transport``.

    ``transport`` is an explicit parameter, not type-introspection on ``mcp``
    (two structurally similar FastMCP classes make isinstance-checks fragile).
    Unknown transport values are rejected BEFORE any registration, so an
    invalid value can never produce a malformed partial surface. The returned
    count is maintained locally (via the ``registered`` list below), not by
    inspecting either engine's private tool-manager internals.
    """
    if transport not in ("stdio", "http"):
        raise ValueError(f"unknown transport: {transport!r} (expected 'stdio' or 'http')")

    registered: list = []

    def _writes_allowed() -> bool:
        """Read config + env fresh on EVERY call -- never cached at
        import/registration time, so a test's or operator's override
        always takes effect immediately. Mirrors server.py:90's
        RUN_TESTS_ON_START truthy-parsing convention verbatim for
        FORTIGATE_MCP_ALLOW_WRITES.
        """
        if tools.config.server.allow_writes:
            return True
        return os.getenv("FORTIGATE_MCP_ALLOW_WRITES", "0").lower() in ("1", "true", "yes", "on")

    def _gate(fn: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap a write/destructive tool closure with the SEC-01
        read-only-by-default gate. Looks up ``RISK_CLASSIFICATION[fn.__name__]``
        -- an uncaught KeyError here is intentional: an unclassified tool
        must crash registration loudly instead of shipping ungated. Returns
        ``fn`` unchanged for read-classified tools (never gated).

        Denial raises ``ToolError`` -- a protocol-level tool error
        (``CallToolResult.is_error=True``), not ordinary Content, so MCP
        clients can distinguish it mechanically from tool output.
        """
        risk_class = RISK_CLASSIFICATION[fn.__name__]
        if risk_class == "read":
            return fn

        denial_message = (
            f"{fn.__name__} is a {risk_class} tool and this server is running "
            "in read-only mode; set server.allow_writes=true or "
            "FORTIGATE_MCP_ALLOW_WRITES=1 to enable it"
        )

        if asyncio.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                if not _writes_allowed():
                    raise ToolError(denial_message)
                return await fn(*args, **kwargs)
            return async_wrapper

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            if not _writes_allowed():
                raise ToolError(denial_message)
            return fn(*args, **kwargs)
        return sync_wrapper

    def _tool(description: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            registered.append(fn.__name__)
            # Gate is the INNER wrap, mcp.tool() stays OUTER: FastMCP
            # introspects whatever _gate(fn) returns, and functools.wraps
            # keeps that introspectable signature byte-identical to `fn`'s
            # for read-classified tools (_gate returns fn unchanged) and
            # gated tools alike -- this is what keeps the golden schema
            # byte-frozen (SEC-01 must never change tools/list surface).
            return cast(Callable[..., Any], mcp.tool(description=description)(_gate(fn)))
        return decorator

    # --- (A) 24 unconditionally-registered, schema-identical tools ---------

    @_tool(LIST_DEVICES_DESC)
    def list_devices() -> List[Content]:
        return cast(List[Content], tools.device_tools.list_devices())

    @_tool(GET_DEVICE_STATUS_DESC)
    def get_device_status(
        device_id: Annotated[str, Field(description="FortiGate device identifier")]
    ) -> List[Content]:
        return cast(List[Content], tools.device_tools.get_device_status(device_id))

    @_tool(TEST_DEVICE_CONNECTION_DESC)
    def test_device_connection(
        device_id: Annotated[str, Field(description="FortiGate device identifier")]
    ) -> List[Content]:
        return cast(List[Content], tools.device_tools.test_device_connection(device_id))

    @_tool(DISCOVER_VDOMS_DESC)
    def discover_vdoms(
        device_id: Annotated[str, Field(description="FortiGate device identifier")]
    ) -> List[Content]:
        return cast(List[Content], tools.device_tools.discover_vdoms(device_id))

    @_tool(ADD_DEVICE_DESC)
    def add_device(
        device_id: Annotated[str, Field(description="Unique device identifier")],
        host: Annotated[str, Field(description="FortiGate IP address or hostname")],
        port: Annotated[int, Field(description="HTTPS port", default=443)] = 443,
        username: Annotated[Optional[str], Field(description="Username", default=None)] = None,
        password: Annotated[Optional[str], Field(description="Password", default=None)] = None,
        api_token: Annotated[Optional[str], Field(description="API token", default=None)] = None,
        vdom: Annotated[str, Field(description="Virtual Domain", default="root")] = "root",
        verify_ssl: Annotated[bool, Field(description="Verify SSL", default=False)] = False,
        timeout: Annotated[int, Field(description="Timeout in seconds", default=30)] = 30
    ) -> List[Content]:
        return cast(List[Content], tools.device_tools.add_device(
            device_id, host, port, username, password, api_token, vdom, verify_ssl, timeout
        ))

    @_tool(REMOVE_DEVICE_DESC)
    def remove_device(
        device_id: Annotated[str, Field(description="Device identifier to remove")]
    ) -> List[Content]:
        return cast(List[Content], tools.device_tools.remove_device(device_id))

    @_tool(LIST_FIREWALL_POLICIES_DESC)
    def list_firewall_policies(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.firewall_tools.list_policies(device_id, vdom))

    @_tool(CREATE_FIREWALL_POLICY_DESC)
    def create_firewall_policy(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        policy_data: Annotated[dict, Field(description="Policy configuration as JSON")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.firewall_tools.create_policy(device_id, policy_data, vdom))

    @_tool(UPDATE_FIREWALL_POLICY_DESC)
    def update_firewall_policy(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        policy_id: Annotated[str, Field(description="Policy ID to update")],
        policy_data: Annotated[dict, Field(description="Updated policy configuration")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.firewall_tools.update_policy(device_id, policy_id, policy_data, vdom))

    @_tool(DELETE_FIREWALL_POLICY_DESC)
    def delete_firewall_policy(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        policy_id: Annotated[str, Field(description="Policy ID to delete")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.firewall_tools.delete_policy(device_id, policy_id, vdom))

    @_tool(LIST_ADDRESS_OBJECTS_DESC)
    def list_address_objects(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.network_tools.list_address_objects(device_id, vdom))

    @_tool(LIST_SERVICE_OBJECTS_DESC)
    def list_service_objects(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.network_tools.list_service_objects(device_id, vdom))

    @_tool(LIST_STATIC_ROUTES_DESC)
    def list_static_routes(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.routing_tools.list_static_routes(device_id, vdom))

    @_tool(GET_ROUTING_TABLE_DESC)
    def get_routing_table(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.routing_tools.get_routing_table(device_id, vdom))

    @_tool(LIST_INTERFACES_DESC)
    def list_interfaces(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.routing_tools.list_interfaces(device_id, vdom))

    @_tool(GET_INTERFACE_STATUS_DESC)
    def get_interface_status(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        interface_name: Annotated[str, Field(description="Interface name")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.routing_tools.get_interface_status(device_id, interface_name, vdom))

    @_tool(UPDATE_STATIC_ROUTE_DESC)
    def update_static_route(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        route_id: Annotated[str, Field(description="Route identifier")],
        route_data: Annotated[dict, Field(description="Route configuration")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.routing_tools.update_static_route(device_id, route_id, route_data, vdom))

    @_tool(DELETE_STATIC_ROUTE_DESC)
    def delete_static_route(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        route_id: Annotated[str, Field(description="Route identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.routing_tools.delete_static_route(device_id, route_id, vdom))

    @_tool(GET_STATIC_ROUTE_DETAIL_DESC)
    def get_static_route_detail(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        route_id: Annotated[str, Field(description="Route identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.routing_tools.get_static_route_detail(device_id, route_id, vdom))

    @_tool(LIST_VIRTUAL_IPS_DESC)
    def list_virtual_ips(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.virtual_ip_tools.list_virtual_ips(device_id, vdom))

    @_tool(CREATE_VIRTUAL_IP_DESC)
    def create_virtual_ip(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        name: Annotated[str, Field(description="Virtual IP name")],
        extip: Annotated[str, Field(description="External IP address")],
        mappedip: Annotated[str, Field(description="Mapped internal IP address")],
        extintf: Annotated[str, Field(description="External interface name")],
        portforward: Annotated[str, Field(description="Enable/disable port forwarding", default="disable")] = "disable",
        protocol: Annotated[str, Field(description="Protocol type", default="tcp")] = "tcp",
        extport: Annotated[Optional[str], Field(description="External port")] = None,
        mappedport: Annotated[Optional[str], Field(description="Mapped port")] = None,
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.virtual_ip_tools.create_virtual_ip(
            device_id, name, extip, mappedip, extintf, portforward, protocol, extport, mappedport, vdom
        ))

    @_tool(UPDATE_VIRTUAL_IP_DESC)
    def update_virtual_ip(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        name: Annotated[str, Field(description="Virtual IP name")],
        vip_data: Annotated[dict, Field(description="Virtual IP configuration")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.virtual_ip_tools.update_virtual_ip(device_id, name, vip_data, vdom))

    @_tool(GET_VIRTUAL_IP_DETAIL_DESC)
    def get_virtual_ip_detail(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        name: Annotated[str, Field(description="Virtual IP name")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.virtual_ip_tools.get_virtual_ip_detail(device_id, name, vdom))

    @_tool(DELETE_VIRTUAL_IP_DESC)
    def delete_virtual_ip(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        name: Annotated[str, Field(description="Virtual IP name")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.virtual_ip_tools.delete_virtual_ip(device_id, name, vdom))

    # --- (B) get_firewall_policy_detail: unified to ONE async definition ---
    # firewall.py's sync and async policy-detail method bodies are
    # byte-identical except for the async keyword -- safe to register a
    # single async def for BOTH transports.

    @_tool("Get detailed information for a specific firewall policy")
    async def get_firewall_policy_detail(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        policy_id: Annotated[str, Field(description="Policy ID to get details for")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], await tools.firewall_tools.get_policy_detail_async(device_id, policy_id, vdom))

    # --- (C) 3 divergent create-tools: transport-marked variants -----------
    # Locked CONS-01 decision: dict payload on stdio vs individual fields on
    # HTTP, dispatching to genuinely different Tools-layer methods.

    if transport == "stdio":
        @_tool(CREATE_ADDRESS_OBJECT_DESC)
        def create_address_object(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            address_data: Annotated[dict, Field(description="Address object configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ) -> List[Content]:
            return cast(List[Content], tools.network_tools.create_address_object_from_payload(device_id, address_data, vdom))
    else:  # http
        @_tool("Create address object")
        def create_address_object(device_id: str, name: str, address_type: str, address: str, vdom: Optional[str] = None) -> List[Content]:
            return cast(List[Content], tools.network_tools.create_address_object(device_id, name, address_type, address, vdom))

    if transport == "stdio":
        @_tool(CREATE_SERVICE_OBJECT_DESC)
        def create_service_object(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            service_data: Annotated[dict, Field(description="Service object configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ) -> List[Content]:
            return cast(List[Content], tools.network_tools.create_service_object_from_payload(device_id, service_data, vdom))
    else:  # http
        @_tool("Create service object")
        def create_service_object(device_id: str, name: str, service_type: str, protocol: str,
                                   port: Optional[str] = None, vdom: Optional[str] = None) -> List[Content]:
            return cast(List[Content], tools.network_tools.create_service_object(device_id, name, service_type, protocol, port, vdom))

    if transport == "stdio":
        @_tool(CREATE_STATIC_ROUTE_DESC)
        def create_static_route(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            route_data: Annotated[dict, Field(description="Route configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ) -> List[Content]:
            return cast(List[Content], tools.routing_tools.create_static_route_from_payload(device_id, route_data, vdom))
    else:  # http
        @_tool("Create static route")
        def create_static_route(device_id: str, dst: str, gateway: str, device: Optional[str] = None, vdom: Optional[str] = None) -> List[Content]:
            return cast(List[Content], tools.routing_tools.create_static_route(device_id, dst, gateway, device, vdom))

    # --- (C2) extended surface: 27 schema-identical tools on both transports

    @_tool(LIST_ADDRESS_GROUPS_DESC)
    def list_address_groups(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.network_tools.list_address_groups(device_id, vdom))

    @_tool(GET_ADDRESS_GROUP_DETAIL_DESC)
    def get_address_group_detail(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        name: Annotated[str, Field(description="Address group name")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.network_tools.get_address_group_detail(device_id, name, vdom))

    @_tool(CREATE_ADDRESS_GROUP_DESC)
    def create_address_group(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        name: Annotated[str, Field(description="New address group name")],
        members: Annotated[List[str], Field(description="Existing address object names")],
        comment: Annotated[Optional[str], Field(description="Comment", default=None)] = None,
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.network_tools.create_address_group(device_id, name, members, comment, vdom))

    @_tool(ADD_ADDRESS_GROUP_MEMBERS_DESC)
    def add_address_group_members(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        name: Annotated[str, Field(description="Address group name")],
        members: Annotated[List[str], Field(description="Address object names to add")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.network_tools.add_address_group_members(device_id, name, members, vdom))

    @_tool(REMOVE_ADDRESS_GROUP_MEMBERS_DESC)
    def remove_address_group_members(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        name: Annotated[str, Field(description="Address group name")],
        members: Annotated[List[str], Field(description="Address object names to remove")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.network_tools.remove_address_group_members(device_id, name, members, vdom))

    @_tool(DELETE_ADDRESS_GROUP_DESC)
    def delete_address_group(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        name: Annotated[str, Field(description="Address group name")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.network_tools.delete_address_group(device_id, name, vdom))

    @_tool(UPDATE_ADDRESS_OBJECT_DESC)
    def update_address_object(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        name: Annotated[str, Field(description="Address object name")],
        address_data: Annotated[dict, Field(description="Fields to change")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.network_tools.update_address_object(device_id, name, address_data, vdom))

    @_tool(DELETE_ADDRESS_OBJECT_DESC)
    def delete_address_object(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        name: Annotated[str, Field(description="Address object name")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.network_tools.delete_address_object(device_id, name, vdom))

    @_tool(UPDATE_SERVICE_OBJECT_DESC)
    def update_service_object(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        name: Annotated[str, Field(description="Service object name")],
        service_data: Annotated[dict, Field(description="Fields to change")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.network_tools.update_service_object(device_id, name, service_data, vdom))

    @_tool(DELETE_SERVICE_OBJECT_DESC)
    def delete_service_object(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        name: Annotated[str, Field(description="Service object name")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.network_tools.delete_service_object(device_id, name, vdom))

    @_tool(LIST_SERVICE_GROUPS_DESC)
    def list_service_groups(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.network_tools.list_service_groups(device_id, vdom))

    @_tool(MOVE_FIREWALL_POLICY_DESC)
    def move_firewall_policy(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        policy_id: Annotated[str, Field(description="Policy ID to move")],
        position: Annotated[Literal["before", "after"], Field(description="Place the policy before or after reference_id")],
        reference_id: Annotated[str, Field(description="Policy ID to position relative to")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.firewall_tools.move_policy(device_id, policy_id, position, reference_id, vdom))

    @_tool(LIST_DHCP_SERVERS_DESC)
    def list_dhcp_servers(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.dhcp_tools.list_dhcp_servers(device_id, vdom))

    @_tool(LIST_DHCP_LEASES_DESC)
    def list_dhcp_leases(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        interface: Annotated[Optional[str], Field(description="Filter by interface name", default=None)] = None,
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.dhcp_tools.list_dhcp_leases(device_id, interface, vdom))

    @_tool(CREATE_DHCP_RESERVATION_DESC)
    def create_dhcp_reservation(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        ip: Annotated[str, Field(description="IPv4 address to reserve")],
        mac: Annotated[str, Field(description="MAC address (aa:bb:cc:dd:ee:ff)")],
        description: Annotated[Optional[str], Field(description="Description", default=None)] = None,
        dhcp_server_id: Annotated[Optional[str], Field(description="DHCP server ID", default=None)] = None,
        interface: Annotated[Optional[str], Field(description="Interface whose DHCP server to use", default=None)] = None,
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.dhcp_tools.create_dhcp_reservation(
            device_id, ip, mac, description, dhcp_server_id, interface, vdom
        ))

    @_tool(DELETE_DHCP_RESERVATION_DESC)
    def delete_dhcp_reservation(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        dhcp_server_id: Annotated[Optional[str], Field(description="DHCP server ID", default=None)] = None,
        reservation_id: Annotated[Optional[str], Field(description="Reservation entry ID", default=None)] = None,
        ip: Annotated[Optional[str], Field(description="Reserved IPv4 address", default=None)] = None,
        mac: Annotated[Optional[str], Field(description="Reserved MAC address", default=None)] = None,
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.dhcp_tools.delete_dhcp_reservation(
            device_id, dhcp_server_id, reservation_id, ip, mac, vdom
        ))

    @_tool(LIST_SECURITY_PROFILES_DESC)
    def list_security_profiles(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        profile_type: Annotated[Literal["application", "webfilter", "antivirus", "ips", "dnsfilter", "ssl-ssh"],
                                Field(description="Profile type")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.security_tools.list_security_profiles(device_id, profile_type, vdom))

    @_tool(GET_SECURITY_PROFILE_DETAIL_DESC)
    def get_security_profile_detail(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        profile_type: Annotated[Literal["application", "webfilter", "antivirus", "ips", "dnsfilter", "ssl-ssh"],
                                Field(description="Profile type")],
        name: Annotated[str, Field(description="Profile name")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.security_tools.get_security_profile_detail(device_id, profile_type, name, vdom))

    @_tool(LIST_IPSEC_TUNNELS_DESC)
    def list_ipsec_tunnels(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.vpn_tools.list_ipsec_tunnels(device_id, vdom))

    @_tool(LIST_SSL_VPN_SESSIONS_DESC)
    def list_ssl_vpn_sessions(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.vpn_tools.list_ssl_vpn_sessions(device_id, vdom))

    @_tool(LIST_LOCAL_USERS_DESC)
    def list_local_users(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.user_tools.list_local_users(device_id, vdom))

    @_tool(LIST_USER_GROUPS_DESC)
    def list_user_groups(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.user_tools.list_user_groups(device_id, vdom))

    @_tool(LIST_FIREWALL_AUTH_SESSIONS_DESC)
    def list_firewall_auth_sessions(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.user_tools.list_firewall_auth_sessions(device_id, vdom))

    @_tool(GET_SYSTEM_RESOURCES_DESC)
    def get_system_resources(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.system_tools.get_system_resources(device_id, vdom))

    @_tool(LIST_ACTIVE_SESSIONS_DESC)
    def list_active_sessions(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        source_ip: Annotated[Optional[str], Field(description="Source IPv4 filter", default=None)] = None,
        destination_ip: Annotated[Optional[str], Field(description="Destination IPv4 filter", default=None)] = None,
        destination_port: Annotated[Optional[int], Field(description="Destination port filter", default=None)] = None,
        policy_id: Annotated[Optional[str], Field(description="Policy ID filter", default=None)] = None,
        count: Annotated[int, Field(description="Maximum sessions to return", default=50)] = 50,
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.system_tools.list_active_sessions(
            device_id, source_ip, destination_ip, destination_port, policy_id, count, vdom
        ))

    @_tool(QUERY_TRAFFIC_LOG_DESC)
    def query_traffic_log(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        source_ip: Annotated[Optional[str], Field(description="Source IPv4 filter", default=None)] = None,
        destination_ip: Annotated[Optional[str], Field(description="Destination IPv4 filter", default=None)] = None,
        destination_port: Annotated[Optional[int], Field(description="Destination port filter", default=None)] = None,
        policy_id: Annotated[Optional[str], Field(description="Policy ID filter", default=None)] = None,
        action: Annotated[Optional[str], Field(description="Action filter (deny, accept, close, ...)", default=None)] = None,
        rows: Annotated[int, Field(description="Maximum records", default=50)] = 50,
        source: Annotated[Literal["memory", "disk"], Field(description="Log source", default="memory")] = "memory",
        raw_filter: Annotated[Optional[str], Field(description="Raw FortiOS filter expression", default=None)] = None,
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.system_tools.query_traffic_log(
            device_id, source_ip, destination_ip, destination_port, policy_id, action, rows, source, raw_filter, vdom
        ))

    @_tool(BACKUP_CONFIG_DESC)
    def backup_config(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        output_path: Annotated[str, Field(description="Absolute file path to write on the MCP host")],
        scope: Annotated[Literal["global", "vdom"], Field(description="Backup scope", default="global")] = "global",
        overwrite: Annotated[bool, Field(description="Replace an existing file", default=False)] = False,
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.system_tools.backup_config(device_id, output_path, scope, overwrite, vdom))

    # --- (C3) generic pass-through -----------------------------------------

    @_tool(CMDB_LIST_DESC)
    def cmdb_list(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        path: Annotated[str, Field(description="cmdb table path, e.g. firewall/policy")],
        filter_expr: Annotated[Optional[str], Field(description="FortiOS filter expression(s), '&'-joined", default=None)] = None,
        start: Annotated[Optional[int], Field(description="Pagination offset", default=None)] = None,
        count: Annotated[Optional[int], Field(description="Maximum objects to return", default=None)] = None,
        format_fields: Annotated[Optional[str], Field(description="'|'-separated fields to return", default=None)] = None,
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.generic_tools.cmdb_list(device_id, path, filter_expr, start, count, format_fields, vdom))

    @_tool(CMDB_GET_DESC)
    def cmdb_get(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        path: Annotated[str, Field(description="cmdb table path")],
        key: Annotated[str, Field(description="Object key")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.generic_tools.cmdb_get(device_id, path, key, vdom))

    @_tool(CREATE_CMDB_OBJECT_DESC)
    def create_cmdb_object(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        path: Annotated[str, Field(description="cmdb table path")],
        data: Annotated[dict, Field(description="Object payload (FortiOS field names)")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.generic_tools.create_cmdb_object(device_id, path, data, vdom))

    @_tool(UPDATE_CMDB_OBJECT_DESC)
    def update_cmdb_object(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        path: Annotated[str, Field(description="cmdb table path")],
        key: Annotated[str, Field(description="Object key")],
        data: Annotated[dict, Field(description="Fields to change")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.generic_tools.update_cmdb_object(device_id, path, key, data, vdom))

    @_tool(DELETE_CMDB_OBJECT_DESC)
    def delete_cmdb_object(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        path: Annotated[str, Field(description="cmdb table path")],
        key: Annotated[str, Field(description="Object key")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.generic_tools.delete_cmdb_object(device_id, path, key, vdom))

    @_tool(MONITOR_GET_DESC)
    def monitor_get(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        path: Annotated[str, Field(description="monitor path, e.g. system/status")],
        params: Annotated[Optional[dict], Field(description="Query parameters", default=None)] = None,
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.generic_tools.monitor_get(device_id, path, params, vdom))

    @_tool(EXECUTE_MONITOR_ACTION_DESC)
    def execute_monitor_action(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        path: Annotated[str, Field(description="monitor action path, e.g. vpn/ipsec/tunnel_down")],
        data: Annotated[Optional[dict], Field(description="JSON body", default=None)] = None,
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.generic_tools.execute_monitor_action(device_id, path, data, vdom))

    @_tool(LOG_GET_DESC)
    def log_get(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        path: Annotated[str, Field(description="log path, e.g. memory/event/system")],
        rows: Annotated[int, Field(description="Maximum records", default=50)] = 50,
        filter_expr: Annotated[Optional[str], Field(description="FortiOS filter expression(s), '&'-joined", default=None)] = None,
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.generic_tools.log_get(device_id, path, rows, filter_expr, vdom))

    # --- (C4) parameterized diagnostics -------------------------------------

    @_tool(LOOKUP_POLICY_DESC)
    def lookup_policy(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        source_ip: Annotated[str, Field(description="Source IPv4 address")],
        destination_ip: Annotated[str, Field(description="Destination IPv4 address")],
        destination_port: Annotated[int, Field(description="Destination port")],
        protocol: Annotated[str, Field(description="tcp, udp, icmp, sctp or protocol number", default="tcp")] = "tcp",
        source_interface: Annotated[Optional[str], Field(description="Ingress interface name", default=None)] = None,
        source_port: Annotated[Optional[int], Field(description="Source port", default=None)] = None,
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.firewall_tools.lookup_policy(
            device_id, source_ip, destination_ip, destination_port, protocol, source_interface, source_port, vdom
        ))

    @_tool(LOOKUP_ROUTE_DESC)
    def lookup_route(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        destination: Annotated[str, Field(description="Destination IPv4 address")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.routing_tools.lookup_route(device_id, destination, vdom))

    @_tool(EXECUTE_IPSEC_TUNNEL_ACTION_DESC)
    def execute_ipsec_tunnel_action(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        phase1_name: Annotated[str, Field(description="Phase-1 interface name")],
        action: Annotated[Literal["up", "down"], Field(description="Bring the tunnel up or down")],
        phase2_name: Annotated[Optional[str], Field(description="Phase-2 selector name", default=None)] = None,
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.vpn_tools.execute_ipsec_tunnel_action(device_id, phase1_name, action, phase2_name, vdom))

    @_tool(GET_FORTIVIEW_TOP_DESC)
    def get_fortiview_top(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        report_by: Annotated[Literal["source", "destination", "application", "threat", "country", "policy", "interface", "website", "web_category"],
                             Field(description="Dimension to report on", default="source")] = "source",
        count: Annotated[int, Field(description="Rows to return", default=20)] = 20,
        sort_by: Annotated[Literal["bytes", "sessions", "bandwidth"], Field(description="Sort key", default="bytes")] = "bytes",
        source_interface: Annotated[Optional[str], Field(description="Source interface filter", default=None)] = None,
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.system_tools.get_fortiview_top(device_id, report_by, count, sort_by, source_interface, vdom))

    @_tool(PING_FROM_DEVICE_DESC)
    def ping_from_device(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        target: Annotated[str, Field(description="IPv4 address or hostname to ping")],
        source_interface: Annotated[Optional[str], Field(description="Source interface", default=None)] = None,
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.system_tools.ping_from_device(device_id, target, source_interface, vdom))

    @_tool(GEOIP_LOOKUP_DESC)
    def geoip_lookup(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        ip: Annotated[str, Field(description="IPv4 address")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.system_tools.geoip_lookup(device_id, ip, vdom))

    @_tool(QUERY_EVENT_LOG_DESC)
    def query_event_log(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        category: Annotated[str, Field(description="Event category (system, vpn, user, router, wireless, ...)", default="system")] = "system",
        rows: Annotated[int, Field(description="Maximum records", default=50)] = 50,
        raw_filter: Annotated[Optional[str], Field(description="Raw FortiOS filter expression", default=None)] = None,
        source: Annotated[Literal["memory", "disk"], Field(description="Log source", default="memory")] = "memory",
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.system_tools.query_event_log(device_id, category, rows, raw_filter, source, vdom))

    @_tool(QUERY_UTM_LOG_DESC)
    def query_utm_log(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        log_type: Annotated[str, Field(description="UTM log type (webfilter, app-ctrl, ips, virus, dns, ...)", default="webfilter")] = "webfilter",
        rows: Annotated[int, Field(description="Maximum records", default=50)] = 50,
        source_ip: Annotated[Optional[str], Field(description="Source IPv4 filter", default=None)] = None,
        raw_filter: Annotated[Optional[str], Field(description="Raw FortiOS filter expression", default=None)] = None,
        source: Annotated[Literal["memory", "disk"], Field(description="Log source", default="memory")] = "memory",
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.system_tools.query_utm_log(device_id, log_type, rows, source_ip, raw_filter, source, vdom))

    @_tool(GET_LOG_SETTINGS_DESC)
    def get_log_settings(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.system_tools.get_log_settings(device_id, vdom))

    # --- (C5) declarative catalog: one (device_id, vdom) read tool per entry

    def _catalog_tool(entry: Any) -> Callable[..., Any]:
        def catalog_fn(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ) -> List[Content]:
            return cast(List[Content], tools.catalog_tools.run(entry.name, device_id, vdom))
        catalog_fn.__name__ = entry.name
        catalog_fn.__qualname__ = entry.name
        catalog_fn.__doc__ = entry.description
        return catalog_fn

    for _entry in CATALOG:
        _tool(_entry.description)(_catalog_tool(_entry))

    # --- (D) stdio-only: health_check, get_server_info ----------------------

    if transport == "stdio":
        @_tool(HEALTH_CHECK_DESC)
        async def health_check() -> List[Content]:
            failed_devices = tools.fortigate_manager.failed_devices
            if failed_devices:
                status = "degraded"
            elif tools._tests_passed is True:
                status = "healthy"
            elif tools._tests_passed is False:
                status = "degraded"
            else:
                status = "unknown"
            details = {
                "registered_devices": len(tools.fortigate_manager.devices),
                "failed_devices": failed_devices,
                "server_version": tools.config.server.version,
                "timestamp": datetime.now().isoformat()
            }
            return FortiGateFormatters.format_health_status(status, details)

        @_tool(GET_SERVER_INFO_DESC)
        async def get_server_info() -> List[Content]:
            info = {
                "name": tools.config.server.name,
                "version": tools.config.server.version,
                "host": tools.config.server.host,
                "port": tools.config.server.port,
                "registered_devices": len(tools.fortigate_manager.devices),
                "failed_devices": tools.fortigate_manager.failed_devices,
                # Derived from the registry's own `registered` list (fully
                # populated by the time any tool call executes) -- never a
                # hand-maintained inventory, which drifted to 20 claimed vs
                # 30 registered before this was derived.
                "tool_count": len(registered),
                "available_tools": sorted(registered),
            }
            return FortiGateFormatters.format_json_response(info, "Server Information")

    # --- (E) http-only: test_connection, health, get_schema_info -----------
    # These use the module-level _format_json_response helper (mirroring
    # server_http.py's local self._format_response), not FortiGateFormatters.

    if transport == "http":
        @_tool("Test FortiGate connection")
        def test_connection() -> List[Content]:
            try:
                devices = tools.fortigate_manager.list_devices()
                connection_results = {}

                for device_id in devices:
                    try:
                        api_client = tools.fortigate_manager.get_device(device_id)
                        success = api_client.test_connection()
                        connection_results[device_id] = {
                            "connected": success,
                            "status": "connected" if success else "failed"
                        }
                    except Exception as e:
                        connection_results[device_id] = {
                            "connected": False,
                            "status": "error",
                            "error": str(e)
                        }

                return _format_json_response({
                    "devices": connection_results,
                    "total_devices": len(devices)
                }, "test_connection", logger=getattr(tools, "logger", None))
            except Exception as e:
                return _format_json_response({
                    "success": False,
                    "error": str(e)
                }, "test_connection", logger=getattr(tools, "logger", None))

        @_tool("Health check for FortiGate MCP server")
        def health() -> List[Content]:
            failed_devices = tools.fortigate_manager.failed_devices
            health_info = {
                "status": "degraded" if failed_devices else "ok",
                "server": "FortiGateMCP-HTTP",
                "timestamp": datetime.now().isoformat(),
                "registered_devices": len(tools.fortigate_manager.devices),
                "failed_devices": failed_devices,
                "device_connections": {}
            }

            try:
                devices = tools.fortigate_manager.list_devices()
                for device_id in devices:
                    try:
                        api_client = tools.fortigate_manager.get_device(device_id)
                        success = api_client.test_connection()
                        health_info["device_connections"][device_id] = "connected" if success else "disconnected"
                    except Exception:
                        health_info["device_connections"][device_id] = "error"
                        health_info["status"] = "degraded"
            except Exception as e:
                health_info["status"] = "error"
                health_info["error"] = str(e)

            return _format_json_response(health_info, "health", logger=getattr(tools, "logger", None))

        @_tool("Get schema information for all available tools")
        def get_schema_info() -> List[Content]:
            schema_info = {
                "server": "FortiGateMCP-HTTP",
                "version": tools.config.server.version,
                "endpoint": f"http://{tools.host}:{tools.port}{tools.path}",
                "tools": {
                    "device_tools": tools.device_tools.get_schema_info(),
                    "firewall_tools": tools.firewall_tools.get_schema_info(),
                    "network_tools": tools.network_tools.get_schema_info(),
                    "routing_tools": tools.routing_tools.get_schema_info(),
                    "virtual_ip_tools": tools.virtual_ip_tools.get_schema_info(),
                    "dhcp_tools": tools.dhcp_tools.get_schema_info(),
                    "security_tools": tools.security_tools.get_schema_info(),
                    "vpn_tools": tools.vpn_tools.get_schema_info(),
                    "user_tools": tools.user_tools.get_schema_info(),
                    "system_tools": tools.system_tools.get_schema_info(),
                    "generic_tools": tools.generic_tools.get_schema_info(),
                    "catalog_tools": tools.catalog_tools.get_schema_info(),
                }
            }
            return _format_json_response(schema_info, "get_schema_info", logger=getattr(tools, "logger", None))

    return len(registered)
