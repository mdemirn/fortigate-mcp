"""
Tool definitions and descriptions for FortiGate MCP tools.

This module contains the descriptions and metadata for all MCP tools
provided by the FortiGate MCP server. These descriptions are used
for tool registration and help documentation.
"""

# Device Management Tool Descriptions
LIST_DEVICES_DESC = """
List the identifiers of all registered FortiGate devices.

This tool returns the device IDs of every FortiGate currently registered with
the MCP server. Use get_device_status with a specific device ID to retrieve
that device's system, connection, and configuration details.

Returns:
- The registered device IDs
"""

GET_DEVICE_STATUS_DESC = """
Get detailed system status information for a specific FortiGate device.

This tool retrieves comprehensive system information from a FortiGate device,
including hardware details, software version, hostname, and operational status.

Parameters:
- device_id: Identifier of the FortiGate device to query

Returns:
- Device model and serial number
- Software version and build
- System hostname
- Current operational status
- Virtual Domain information
"""

TEST_DEVICE_CONNECTION_DESC = """
Test network connectivity to a specific FortiGate device.

This tool performs a connection test to verify that the MCP server can
successfully communicate with the specified FortiGate device.

Parameters:
- device_id: Identifier of the FortiGate device to test

Returns:
- Connection status (success/failure)
- Response time information
- Error details if connection fails
"""

ADD_DEVICE_DESC = """
Add a new FortiGate device to the MCP server.

This tool registers a new FortiGate device with the server, configuring
connection parameters and authentication credentials.

Parameters:
- device_id: Unique identifier for the new device
- host: IP address or hostname of the FortiGate device
- port: HTTPS port (default: 443)
- username: Username for authentication (if not using API token)
- password: Password for authentication (if not using API token)
- api_token: API token for authentication (preferred method)
- vdom: Virtual Domain name (default: "root")
- verify_ssl: Whether to verify SSL certificates (default: false)
- timeout: Connection timeout in seconds (default: 30)

Returns:
- Registration status
- Device configuration summary
"""

REMOVE_DEVICE_DESC = """
Remove a FortiGate device from the MCP server.

This tool unregisters a FortiGate device from the server, removing
all associated configuration and terminating active connections.

Parameters:
- device_id: Identifier of the device to remove

Returns:
- Removal status confirmation
"""

DISCOVER_VDOMS_DESC = """
Discover and list all Virtual Domains (VDOMs) on a FortiGate device.

This tool queries the specified FortiGate device to retrieve information
about all configured Virtual Domains, including their status and settings.

Parameters:
- device_id: Identifier of the FortiGate device to query

Returns:
- List of VDOMs with their configuration
- VDOM status (enabled/disabled)
- Resource allocation information
"""

# Firewall Policy Tool Descriptions
LIST_FIREWALL_POLICIES_DESC = """
List all firewall policies configured on a FortiGate device.

This tool retrieves and displays all firewall security policies from the
specified device and Virtual Domain, showing traffic control rules and settings.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Policy ID and name
- Source and destination addresses
- Services and ports
- Action (allow/deny)
- Policy status (enabled/disabled)
"""

CREATE_FIREWALL_POLICY_DESC = """
Create a new firewall policy on a FortiGate device.

This tool adds a new security policy to control traffic flow through
the FortiGate device, defining rules for source, destination, and services.

Parameters:
- device_id: Identifier of the FortiGate device
- policy_data: Policy configuration as JSON object
- vdom: Virtual Domain name (optional, uses device default)

Policy data should include:
- name: Policy name
- srcintf: Source interface(s)
- dstintf: Destination interface(s)
- srcaddr: Source address object(s)
- dstaddr: Destination address object(s)
- service: Service object(s)
- action: accept or deny

Returns:
- Creation status
- Policy ID assigned
- Configuration summary
"""

UPDATE_FIREWALL_POLICY_DESC = """
Update an existing firewall policy on a FortiGate device.

This tool modifies the configuration of an existing firewall policy,
allowing changes to rules, addresses, services, and other settings.

Parameters:
- device_id: Identifier of the FortiGate device
- policy_id: ID of the policy to update
- policy_data: Updated policy configuration as JSON object
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Update status
- Configuration changes applied
"""

DELETE_FIREWALL_POLICY_DESC = """
Delete a firewall policy from a FortiGate device.

This tool removes an existing firewall policy from the device configuration,
permanently deleting the specified security rule.

Parameters:
- device_id: Identifier of the FortiGate device
- policy_id: ID of the policy to delete
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Deletion status confirmation
"""

# Network Objects Tool Descriptions
LIST_ADDRESS_OBJECTS_DESC = """
List all address objects configured on a FortiGate device.

This tool retrieves all network address objects defined on the device,
including IP addresses, subnets, ranges, and FQDN objects.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Object name and type
- IP address or subnet configuration
- Comments and descriptions
"""

CREATE_ADDRESS_OBJECT_DESC = """
Create a new address object on a FortiGate device.

This tool adds a new network address object that can be used in
firewall policies and other security rules.

Parameters:
- device_id: Identifier of the FortiGate device
- address_data: Address object configuration as JSON
- vdom: Virtual Domain name (optional, uses device default)

Address data should include:
- name: Object name
- type: ipmask, iprange, or fqdn
- subnet: IP/netmask (for ipmask type)
- start-ip/end-ip: IP range (for iprange type)
- fqdn: Domain name (for fqdn type)
- comment: Optional description

Returns:
- Creation status
- Object configuration summary
"""

LIST_SERVICE_OBJECTS_DESC = """
List all service objects configured on a FortiGate device.

This tool retrieves all network service objects defined on the device,
including TCP/UDP port definitions and protocol specifications.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Service name and protocol
- Port configurations
- Comments and descriptions
"""

CREATE_SERVICE_OBJECT_DESC = """
Create a new service object on a FortiGate device.

This tool adds a new network service object that defines protocols
and ports for use in firewall policies.

Parameters:
- device_id: Identifier of the FortiGate device
- service_data: Service object configuration as JSON
- vdom: Virtual Domain name (optional, uses device default)

Service data should include:
- name: Service name
- protocol: TCP, UDP, or ICMP
- tcp-portrange: TCP port range (for TCP)
- udp-portrange: UDP port range (for UDP)
- comment: Optional description

Returns:
- Creation status
- Service configuration summary
"""

# Virtual IP Tool Descriptions
LIST_VIRTUAL_IPS_DESC = """
List all Virtual IPs configured on a FortiGate device.

This tool retrieves all Virtual IP objects defined on the device,
including port forwarding configurations and NAT mappings.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Virtual IP name and configuration
- External and mapped IP addresses
- Port forwarding settings
- Interface assignments
"""

CREATE_VIRTUAL_IP_DESC = """
Create a new Virtual IP on a FortiGate device.

This tool adds a new Virtual IP object that can be used for
port forwarding, NAT, and external access to internal services.

Parameters:
- device_id: Identifier of the FortiGate device
- name: Virtual IP name
- extip: External IP address
- mappedip: Mapped internal IP address
- extintf: External interface name
- portforward: Enable/disable port forwarding (default: disable)
- protocol: Protocol type (tcp/udp, default: tcp)
- extport: External port (optional)
- mappedport: Mapped port (optional)
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Creation status
- Virtual IP configuration summary
"""

UPDATE_VIRTUAL_IP_DESC = """
Update an existing Virtual IP on a FortiGate device.

This tool modifies the configuration of an existing Virtual IP object,
allowing changes to IP addresses, ports, or other settings.

Parameters:
- device_id: Identifier of the FortiGate device
- name: Name of the Virtual IP to update
- vip_data: Updated configuration as JSON
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Update status
- Configuration changes applied
"""

GET_VIRTUAL_IP_DETAIL_DESC = """
Get detailed information for a specific Virtual IP.

This tool retrieves comprehensive configuration details for a
specific Virtual IP object, including all settings and mappings.

Parameters:
- device_id: Identifier of the FortiGate device
- name: Name of the Virtual IP to query
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Complete Virtual IP configuration
- Port forwarding details
- Interface assignments
- Status information
"""

DELETE_VIRTUAL_IP_DESC = """
Delete a Virtual IP from a FortiGate device.

This tool removes an existing Virtual IP object from the device
configuration. Note that Virtual IPs in use by policies cannot be deleted.

Parameters:
- device_id: Identifier of the FortiGate device
- name: Name of the Virtual IP to delete
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Deletion status confirmation
"""

# Enhanced Routing Tool Descriptions
UPDATE_STATIC_ROUTE_DESC = """
Update an existing static route on a FortiGate device.

This tool modifies the configuration of an existing static route,
allowing changes to destination, gateway, or other settings.

Parameters:
- device_id: Identifier of the FortiGate device
- route_id: ID of the route to update
- route_data: Updated configuration as JSON
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Update status
- Configuration changes applied
"""

DELETE_STATIC_ROUTE_DESC = """
Delete a static route from a FortiGate device.

This tool removes an existing static route from the device
configuration.

Parameters:
- device_id: Identifier of the FortiGate device
- route_id: ID of the route to delete
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Deletion status confirmation
"""

GET_STATIC_ROUTE_DETAIL_DESC = """
Get detailed information for a specific static route.

This tool retrieves comprehensive configuration details for a
specific static route, including all settings and status.

Parameters:
- device_id: Identifier of the FortiGate device
- route_id: ID of the route to query
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Complete route configuration
- Gateway and interface details
- Status information
"""

# Routing Tool Descriptions
LIST_STATIC_ROUTES_DESC = """
List all static routes configured on a FortiGate device.

This tool retrieves all manually configured static routes from the
device's routing table, showing destination networks and gateways.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Route destinations and gateways
- Interface assignments
- Administrative distances
- Route status (enabled/disabled)
"""

CREATE_STATIC_ROUTE_DESC = """
Create a new static route on a FortiGate device.

This tool adds a new static route to the device's routing configuration,
defining how traffic to specific networks should be forwarded.

Parameters:
- device_id: Identifier of the FortiGate device
- route_data: Route configuration as JSON
- vdom: Virtual Domain name (optional, uses device default)

Route data should include:
- dst: Destination network (IP/netmask)
- gateway: Next hop gateway IP
- device: Outgoing interface name
- distance: Administrative distance (optional)
- comment: Optional description

Returns:
- Creation status
- Route configuration summary
"""

GET_ROUTING_TABLE_DESC = """
Get the current routing table from a FortiGate device.

This tool retrieves the active routing table showing all routes
currently installed on the device, including static, dynamic, and connected routes.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Active route entries
- Route sources (static, OSPF, BGP, etc.)
- Metrics and preferences
- Interface assignments
"""

LIST_INTERFACES_DESC = """
List all network interfaces configured on a FortiGate device.

This tool retrieves information about all network interfaces,
including physical ports, VLANs, and virtual interfaces.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Interface names and types
- IP address configurations
- Interface status (up/down)
- VLAN and zone assignments
"""

GET_INTERFACE_STATUS_DESC = """
Get the current status of a specific network interface on a FortiGate device.

This tool retrieves live status information for a single named interface,
including its link state, IP address configuration, and related details.

Parameters:
- device_id: Identifier of the FortiGate device
- interface_name: Name of the specific interface to query
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Interface name
- Link status (up/down)
- IP address configuration
- Related interface detail fields
"""

# System Tool Descriptions
HEALTH_CHECK_DESC = """
Perform a comprehensive health check of the FortiGate MCP server.

This tool checks the overall health and status of the MCP server,
including device connectivity, service availability, and system resources.

Returns:
- Overall server health status
- Registered device count
- Service availability
- Performance metrics
- Error conditions if any
"""

GET_SERVER_INFO_DESC = """
Get detailed information about the FortiGate MCP server.

This tool provides comprehensive information about the server
configuration, capabilities, and current operational status.

Returns:
- Server version and build information
- Available tools and capabilities
- Configuration summary
- Runtime statistics
- API endpoints
"""

# ---------------------------------------------------------------------------
# Extended tool surface: address groups, object update/delete, policy
# ordering, DHCP, security profiles, VPN, users, system monitoring.
# ---------------------------------------------------------------------------

LIST_ADDRESS_GROUPS_DESC = """
List address groups on a FortiGate device with their member names.

Address groups bundle address objects (and other groups) so one policy entry
can reference many hosts/subnets. Use get_address_group_detail to resolve the
members to IP values.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Group name, member count, member names, excluded members, comment
"""

GET_ADDRESS_GROUP_DETAIL_DESC = """
Show one address group with every member resolved to its subnet, range or FQDN.

Parameters:
- device_id: Identifier of the FortiGate device
- name: Address group name (exact match)
- vdom: Virtual Domain name (optional)

Returns:
- Group metadata and each member with its resolved value (nested groups are listed with their members)
"""

CREATE_ADDRESS_GROUP_DESC = """
Create a new address group from existing address object names.

Parameters:
- device_id: Identifier of the FortiGate device
- name: Name for the new group (letters, digits, underscore, hyphen)
- members: List of existing address object (or group) names; at least one is required
- comment: Optional description
- vdom: Virtual Domain name (optional)

Returns:
- Creation status
"""

ADD_ADDRESS_GROUP_MEMBERS_DESC = """
Add address objects to an existing address group, keeping the current members.

Typical use: grant a new PC an exception that a policy already applies to the
group (e.g. add a host object to an "allowed" group instead of editing the policy).

Parameters:
- device_id: Identifier of the FortiGate device
- name: Address group name
- members: Address object names to add (already-present names are skipped)
- vdom: Virtual Domain name (optional)

Returns:
- Which members were added and the new member count
"""

REMOVE_ADDRESS_GROUP_MEMBERS_DESC = """
Remove address objects from an address group.

FortiOS requires a group to keep at least one member; removing the last member
is refused -- delete the group instead.

Parameters:
- device_id: Identifier of the FortiGate device
- name: Address group name
- members: Address object names to remove
- vdom: Virtual Domain name (optional)

Returns:
- Which members were removed and the new member count
"""

DELETE_ADDRESS_GROUP_DESC = """
Delete an address group. FortiOS refuses while a policy still references the group.

Parameters:
- device_id: Identifier of the FortiGate device
- name: Address group name
- vdom: Virtual Domain name (optional)

Returns:
- Deletion status
"""

UPDATE_ADDRESS_OBJECT_DESC = """
Update an existing address object (comment, subnet, range, FQDN, ...).

Only the fields present in address_data change; FortiOS merges them into the
object. Example address_data: {"subnet": "192.0.2.40 255.255.255.255", "comment": "HR workstation"}

Parameters:
- device_id: Identifier of the FortiGate device
- name: Address object name
- address_data: Fields to change as JSON object
- vdom: Virtual Domain name (optional)

Returns:
- Update status
"""

DELETE_ADDRESS_OBJECT_DESC = """
Delete an address object. FortiOS refuses while a policy or group still references it.

Parameters:
- device_id: Identifier of the FortiGate device
- name: Address object name
- vdom: Virtual Domain name (optional)

Returns:
- Deletion status
"""

UPDATE_SERVICE_OBJECT_DESC = """
Update an existing custom service object (ports, protocol, comment).

Example service_data: {"tcp-portrange": "3389", "comment": "RDP"}

Parameters:
- device_id: Identifier of the FortiGate device
- name: Service object name
- service_data: Fields to change as JSON object
- vdom: Virtual Domain name (optional)

Returns:
- Update status
"""

DELETE_SERVICE_OBJECT_DESC = """
Delete a custom service object. FortiOS refuses while a policy or service group references it.

Parameters:
- device_id: Identifier of the FortiGate device
- name: Service object name
- vdom: Virtual Domain name (optional)

Returns:
- Deletion status
"""

LIST_SERVICE_GROUPS_DESC = """
List service groups with their member services resolved to protocol/ports.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional)

Returns:
- Group name, members with resolved ports, comment
"""

MOVE_FIREWALL_POLICY_DESC = """
Move a firewall policy before or after another policy in the evaluation order.

FortiGate evaluates policies top-down and applies the first match, so a
host-specific policy must sit above the broader policy it is meant to override.
Newly created policies are appended at the bottom; use this tool to position them.

Parameters:
- device_id: Identifier of the FortiGate device
- policy_id: ID of the policy to move
- position: "before" or "after"
- reference_id: ID of the policy to position relative to
- vdom: Virtual Domain name (optional)

Returns:
- Move status
"""

LIST_DHCP_SERVERS_DESC = """
List DHCP servers configured on a FortiGate device, including their reservations.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional)

Returns:
- Per server: id, interface, status, IP range, gateway/netmask, DNS, lease time,
  reserved addresses (id, ip, mac, description)
"""

LIST_DHCP_LEASES_DESC = """
List active DHCP leases (ip, mac, hostname, interface, expiry, reserved flag).

Useful to find a PC's MAC address before creating a reservation.

Parameters:
- device_id: Identifier of the FortiGate device
- interface: Optional interface name to filter on (e.g. "vlan10")
- vdom: Virtual Domain name (optional)

Returns:
- One line per lease sorted by interface and IP
"""

CREATE_DHCP_RESERVATION_DESC = """
Reserve an IP address for a MAC address on a FortiGate DHCP server.

The DHCP server is selected by dhcp_server_id, else by interface, else
automatically by the server whose range/subnet contains the IP. Duplicate IP or
MAC reservations are rejected before anything is written.

Parameters:
- device_id: Identifier of the FortiGate device
- ip: IPv4 address to reserve
- mac: MAC address (aa:bb:cc:dd:ee:ff)
- description: Optional description (e.g. hostname / owner)
- dhcp_server_id: Optional DHCP server ID (see list_dhcp_servers)
- interface: Optional interface name whose DHCP server should hold the reservation
- vdom: Virtual Domain name (optional)

Returns:
- Creation status with the chosen DHCP server
"""

DELETE_DHCP_RESERVATION_DESC = """
Delete a DHCP reservation identified by reservation_id, ip or mac.

Parameters:
- device_id: Identifier of the FortiGate device
- dhcp_server_id: Optional DHCP server ID to narrow the search
- reservation_id: Optional reservation entry ID (see list_dhcp_servers)
- ip: Optional reserved IPv4 address
- mac: Optional reserved MAC address
- vdom: Virtual Domain name (optional)

Returns:
- Deletion status (ambiguous matches are refused)
"""

LIST_SECURITY_PROFILES_DESC = """
List security (UTM) profiles of one type with a short summary each.

Parameters:
- device_id: Identifier of the FortiGate device
- profile_type: application | webfilter | antivirus | ips | dnsfilter | ssl-ssh
- vdom: Virtual Domain name (optional)

Returns:
- Profile names, comments and a per-type summary (entry counts, block counts, ...)
"""

GET_SECURITY_PROFILE_DETAIL_DESC = """
Show one security profile in depth.

For application control lists the entries are shown in evaluation order with
their action, categories and application signatures (resolved to names). For
web filter profiles the FortiGuard category actions are grouped by action.

Parameters:
- device_id: Identifier of the FortiGate device
- profile_type: application | webfilter | antivirus | ips | dnsfilter | ssl-ssh
- name: Profile name
- vdom: Virtual Domain name (optional)

Returns:
- Profile settings and entries
"""

LIST_IPSEC_TUNNELS_DESC = """
List IPsec VPN tunnels with status, remote gateway, phase-2 selectors and traffic counters.

Dial-up tunnels show the number of connected clients instead of a gateway.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional)

Returns:
- One block per tunnel: state (UP/PARTIAL/DOWN/dialup), gateway, bytes in/out, phase-2 entries
"""

LIST_SSL_VPN_SESSIONS_DESC = """
List active SSL-VPN sessions (user, source host, login time, duration).

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional)

Returns:
- One line per session
"""

LIST_LOCAL_USERS_DESC = """
List local user accounts defined on the FortiGate (status, type, two-factor, email).

Passwords are never returned by FortiOS.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional)

Returns:
- One line per user
"""

LIST_USER_GROUPS_DESC = """
List user groups and their members (local users and remote-server matches).

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional)

Returns:
- Group name, type, members, remote group matches
"""

LIST_FIREWALL_AUTH_SESSIONS_DESC = """
List users currently authenticated against identity-based firewall policies.

Requires an API profile with permission on the user monitor (otherwise FortiOS returns 403).

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional)

Returns:
- Username, source IP, method, duration per authenticated user
"""

GET_SYSTEM_RESOURCES_DESC = """
Show current CPU, memory, disk and session usage of a FortiGate device.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional)

Returns:
- Current values for cpu, memory, disk, sessions, setup rate
"""

LIST_ACTIVE_SESSIONS_DESC = """
Query the live session table with optional filters.

Use it to check whether a host's traffic is actually flowing and which policy
it matched.

Parameters:
- device_id: Identifier of the FortiGate device
- source_ip: Optional source IPv4 address
- destination_ip: Optional destination IPv4 address
- destination_port: Optional destination port
- policy_id: Optional policy ID
- count: Maximum sessions to return (default 50, max 500)
- vdom: Virtual Domain name (optional)

Returns:
- One line per session: protocol, source, destination, policy, duration, bytes, NAT
"""

QUERY_TRAFFIC_LOG_DESC = """
Query forward traffic logs with optional filters (most recent first).

Use it to answer "why is this host blocked / which policy handled this flow".
Memory logs are the default (models without a log disk); pass source="disk"
on models that log to disk.

Parameters:
- device_id: Identifier of the FortiGate device
- source_ip, destination_ip, destination_port, policy_id, action: Optional filters
  (action examples: deny, accept, close, timeout)
- rows: Maximum records (default 50, max 500)
- source: "memory" (default) or "disk"
- raw_filter: Optional FortiOS filter expression, e.g. "srcip==192.0.2.25"
- vdom: Virtual Domain name (optional)

Returns:
- One line per log record: time, action, src -> dst, service, policy, bytes
"""

BACKUP_CONFIG_DESC = """
Download the running configuration and save it to a file on the MCP server host.

Parameters:
- device_id: Identifier of the FortiGate device
- output_path: Absolute file path to write (parent directory must exist)
- scope: "global" (default, whole device) or "vdom"
- overwrite: Replace an existing file (default false)
- vdom: Virtual Domain name (optional)

Returns:
- Saved path, size and line count
"""


# ---------------------------------------------------------------------------
# Generic pass-through and parameterized diagnostics
# ---------------------------------------------------------------------------

CMDB_LIST_DESC = """
List every object of any FortiOS configuration table (GET /api/v2/cmdb/{path}).

The escape hatch for tables that have no dedicated tool. Examples of path:
"firewall/policy", "system/interface", "vpn.ipsec/phase1-interface",
"router/static", "user/local", "wireless-controller/vap", "system/sdwan".
Secret-looking fields (passwords, PSKs, keys) are redacted; large responses are
truncated, so narrow them with filter_expr, count or format_fields.

Parameters:
- device_id: Identifier of the FortiGate device
- path: cmdb table path without the /api/v2/cmdb/ prefix
- filter_expr: Optional FortiOS filter, e.g. "status==enable" or "name=@vlan" ("&" joins several)
- start, count: Optional pagination
- format_fields: Optional "|"-separated field list to return, e.g. "policyid|name|action"
- vdom: Virtual Domain name (optional)

Returns:
- The raw JSON response (results plus metadata)
"""

CMDB_GET_DESC = """
Get one configuration object by key (GET /api/v2/cmdb/{path}/{key}).

Examples: path "firewall/policy" key "56"; path "system/interface" key "port1";
path "vpn.ipsec/phase1-interface" key "branch-vpn". Secret fields are redacted.

Parameters:
- device_id: Identifier of the FortiGate device
- path: cmdb table path
- key: Object key (policy id, object name, interface name, ...)
- vdom: Virtual Domain name (optional)

Returns:
- The raw JSON object
"""

CREATE_CMDB_OBJECT_DESC = """
Create a configuration object in any table from a raw JSON payload (POST /api/v2/cmdb/{path}).

Use the typed create_* tools when one exists; this is for tables without one
(e.g. "firewall/ippool", "firewall.schedule/recurring", "system/zone",
"vpn.ipsec/phase2-interface"). The payload must use FortiOS field names.

Parameters:
- device_id: Identifier of the FortiGate device
- path: cmdb table path
- data: Object payload as JSON (FortiOS field names, e.g. {"name": "...", "member": [{"name": "..."}]})
- vdom: Virtual Domain name (optional)

Returns:
- Creation status and the new object's key when FortiOS reports it
"""

UPDATE_CMDB_OBJECT_DESC = """
Change fields of an existing configuration object (PUT /api/v2/cmdb/{path}/{key}).

Only the fields in data change. Example: path "system/interface", key "vlan60-guest",
data {"description": "Guest Wi-Fi"}.

Parameters:
- device_id: Identifier of the FortiGate device
- path: cmdb table path
- key: Object key
- data: Fields to change as JSON
- vdom: Virtual Domain name (optional)

Returns:
- Update status
"""

DELETE_CMDB_OBJECT_DESC = """
Delete a configuration object from any table (DELETE /api/v2/cmdb/{path}/{key}).

FortiOS refuses while the object is still referenced elsewhere.

Parameters:
- device_id: Identifier of the FortiGate device
- path: cmdb table path
- key: Object key
- vdom: Virtual Domain name (optional)

Returns:
- Deletion status
"""

MONITOR_GET_DESC = """
Read any live-status endpoint (GET /api/v2/monitor/{path}).

Examples: "system/status", "router/ipv4", "vpn/ipsec", "license/status",
"system/interface", "firewall/policy/select", "switch-controller/managed-switch",
"wifi/client". Optional query parameters are passed through as params.

Parameters:
- device_id: Identifier of the FortiGate device
- path: monitor path without the /api/v2/monitor/ prefix
- params: Optional query parameters as JSON object
- vdom: Virtual Domain name (optional)

Returns:
- The raw JSON response (secret fields redacted, large output truncated)
"""

EXECUTE_MONITOR_ACTION_DESC = """
Run a monitor action (POST /api/v2/monitor/{path}): tunnel up/down, session close,
cache flush, user deauthentication, etc.

Examples: path "vpn/ipsec/tunnel_down" data {"p1name": "branch-vpn"};
path "firewall/session/close" data {"saddr": "10.0.0.5", "daddr": "...", "sport": 1, "dport": 443, "pro": "tcp"};
path "user/firewall/deauth" data {"user": "alice", "ip": "10.0.0.5"}.
These change device state and require writes to be enabled.

Parameters:
- device_id: Identifier of the FortiGate device
- path: monitor action path
- data: Optional JSON body
- vdom: Virtual Domain name (optional)

Returns:
- The raw JSON response
"""

LOG_GET_DESC = """
Read raw log records from any log endpoint (GET /api/v2/log/{path}).

path is "{memory|disk}/{type}/{subtype}", e.g. "memory/event/system",
"memory/event/vpn", "memory/utm/webfilter", "memory/traffic/local",
"disk/traffic/forward". Prefer query_traffic_log / query_event_log /
query_utm_log for formatted output.

Parameters:
- device_id: Identifier of the FortiGate device
- path: log path
- rows: Maximum records (default 50, max 500)
- filter_expr: Optional FortiOS filter, e.g. "srcip==10.0.0.5" ("&" joins several)
- vdom: Virtual Domain name (optional)

Returns:
- The raw JSON log records
"""

LOOKUP_POLICY_DESC = """
Ask the FortiGate which firewall policy a hypothetical flow would match
(monitor/firewall/policy-lookup), without sending any traffic.

Use it to answer "would host X reach server Y on port Z, and through which rule?".

Parameters:
- device_id: Identifier of the FortiGate device
- source_ip: Source IPv4 address
- destination_ip: Destination IPv4 address
- destination_port: Destination port
- protocol: tcp (default), udp, icmp, sctp or a protocol number
- source_interface: Optional ingress interface name (improves accuracy)
- source_port: Optional source port
- vdom: Virtual Domain name (optional)

Returns:
- Matching policy id/name/action, or "no matching policy" (implicit deny)
"""

LOOKUP_ROUTE_DESC = """
Ask the routing table which route, interface and gateway reach a destination
(monitor/router/lookup).

Parameters:
- device_id: Identifier of the FortiGate device
- destination: Destination IPv4 address
- vdom: Virtual Domain name (optional)

Returns:
- Matched route details (interface, gateway, type, distance, metric)
"""

EXECUTE_IPSEC_TUNNEL_ACTION_DESC = """
Bring an IPsec tunnel up or down (monitor/vpn/ipsec/tunnel_up | tunnel_down).

Bringing a site-to-site tunnel down interrupts traffic until it renegotiates;
requires writes to be enabled.

Parameters:
- device_id: Identifier of the FortiGate device
- phase1_name: Phase-1 interface name (see list_ipsec_phase1 / list_ipsec_tunnels)
- action: "up" or "down"
- phase2_name: Optional phase-2 selector name (defaults to all selectors of the phase-1)
- vdom: Virtual Domain name (optional)

Returns:
- Action status
"""

GET_FORTIVIEW_TOP_DESC = """
FortiView top talkers from the live session statistics (monitor/fortiview/statistics).

Parameters:
- device_id: Identifier of the FortiGate device
- report_by: source (default), destination, application, threat, country, policy, interface, website, web_category
- count: Rows to return (default 20, max 200)
- sort_by: bytes (default), sessions or bandwidth
- source_interface: Optional source interface filter
- vdom: Virtual Domain name (optional)

Returns:
- One line per entry with sessions, bytes and bandwidth
"""

PING_FROM_DEVICE_DESC = """
Ping a host from the FortiGate itself (monitor/network/diag-icmp-ping), useful to
check reachability from the firewall's own perspective (e.g. through a VPN tunnel).

Parameters:
- device_id: Identifier of the FortiGate device
- target: IPv4 address or hostname to ping
- source_interface: Optional source interface
- vdom: Virtual Domain name (optional)

Returns:
- Packets sent/received and round-trip statistics as reported by the device
"""

GEOIP_LOOKUP_DESC = """
Resolve an IP address to its FortiGuard geolocation (country) via the device.

Parameters:
- device_id: Identifier of the FortiGate device
- ip: IPv4 address
- vdom: Virtual Domain name (optional)

Returns:
- Country and related GeoIP fields
"""

QUERY_EVENT_LOG_DESC = """
Query event logs by category: system (admin logins, config changes), vpn (tunnel
up/down, dial-up logins), user (authentication), router, wireless, endpoint, ha,
sdwan and more.

Parameters:
- device_id: Identifier of the FortiGate device
- category: system (default), vpn, user, router, wireless, endpoint, ha, security-rating, fortiextender, connector, sdwan, cifs, compliance-check
- rows: Maximum records (default 50, max 500)
- raw_filter: Optional FortiOS filter, e.g. "user==admin" or "logdesc=@login"
- source: "memory" (default) or "disk"
- vdom: Virtual Domain name (optional)

Returns:
- One line per record: time, level, description, user, message
"""

QUERY_UTM_LOG_DESC = """
Query UTM (security) logs: webfilter, app-ctrl, ips, virus, dns, emailfilter, dlp,
ssl, anomaly, waf, file-filter, ssh, voip, icap, virtual-patch.

Use it to see which site or application was blocked for a host and by which profile.

Parameters:
- device_id: Identifier of the FortiGate device
- log_type: webfilter (default) or one of the types above
- rows: Maximum records (default 50, max 500)
- source_ip: Optional source IPv4 filter
- raw_filter: Optional FortiOS filter, e.g. "action==blocked"
- source: "memory" (default) or "disk"
- vdom: Virtual Domain name (optional)

Returns:
- One line per record: time, action, src -> dst, hostname/application/attack, policy
"""

GET_LOG_SETTINGS_DESC = """
Show where the device sends logs: memory, disk, syslog, FortiAnalyzer and FortiCloud
settings in one view.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional)

Returns:
- One line per log destination with status, server and key options
"""
