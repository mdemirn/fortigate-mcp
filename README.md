# FortiGate MCP Server

[![Test](https://github.com/mdemirn/fortigate-mcp/actions/workflows/test.yml/badge.svg)](https://github.com/mdemirn/fortigate-mcp/actions/workflows/test.yml)
[![Lint](https://github.com/mdemirn/fortigate-mcp/actions/workflows/lint.yml/badge.svg)](https://github.com/mdemirn/fortigate-mcp/actions/workflows/lint.yml)
[![Security](https://github.com/mdemirn/fortigate-mcp/actions/workflows/security.yml/badge.svg)](https://github.com/mdemirn/fortigate-mcp/actions/workflows/security.yml)
[![Release](https://github.com/mdemirn/fortigate-mcp/actions/workflows/release.yml/badge.svg)](https://github.com/mdemirn/fortigate-mcp/actions/workflows/release.yml)

A Model Context Protocol (MCP) server for FortiGate firewalls. It lets Claude Code,
Claude Desktop, Cursor or any other MCP client read and change FortiOS configuration
through the FortiOS REST API: policies, address and service objects, groups, routes,
VIPs, DHCP, VPN, users, security profiles, live sessions and logs. One server can
manage several FortiGates at once.

It was written against FortiOS 8.0 and uses only the `/api/v2/cmdb`, `/api/v2/monitor`
and `/api/v2/log` endpoints, so FortiOS 7.4 and 7.6 units work as well, apart from
endpoints a given release does not have.

The server exposes 140 unique tools, 275 total tool-surface registrations across stdio
(137) and HTTP (138) transports; three create-tools have transport-specific parameter
shapes. Every tool that changes a device is disabled until you turn writes on.

## What you can do with it

Typical requests, in the words you would use with the assistant:

- "Which policy blocks 192.0.2.25 from reaching the file server on port 445?"
  (`lookup_policy`, `query_traffic_log`, `get_firewall_policy_detail`)
- "Add the new workstation to the remote-support exception group" (`add_address_group_members`)
- "Reserve 192.0.2.40 for this MAC on the client VLAN" (`list_dhcp_leases`,
  `create_dhcp_reservation`)
- "Move rule 12 above rule 7" (`move_firewall_policy`)
- "Which IPsec tunnels are down?" (`list_ipsec_tunnels`)
- "What does the remote-access application profile actually allow?"
  (`get_security_profile_detail`)
- "Who logged into the admin GUI today?" (`query_event_log`)
- "Save a config backup before I touch anything" (`backup_config`)
- Anything else the REST API can do, through `cmdb_list`, `cmdb_get`, `monitor_get`
  and `log_get`.

Policy details resolve every address, address group, service and service group to
its real value, and show the identity restrictions (users/groups) and the security
profiles attached to the rule, so a reader does not have to open four screens to
understand one line of the policy table.

## Requirements

- Python 3.11+ (3.12 or 3.13 recommended; the locked dependency set does not build on
  3.14 yet because `pydantic-core 2.33` ships no wheel for it)
- [`uv`](https://docs.astral.sh/uv/) or `pip`
- A FortiGate reachable over HTTPS and a REST API admin with an API token

## Install

```bash
git clone https://github.com/mdemirn/fortigate-mcp.git
cd fortigate-mcp
uv sync --locked          # installs the locked, reproducible dependency set
```

The repository pins Python 3.12 in `.python-version`; `uv` downloads it if needed.
Without `uv`:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Create the API user on the FortiGate

In the GUI: System > Administrators > Create New > REST API Admin. Pick an admin
profile (a read-only profile is enough for the read tools; writes need a profile with
the matching permissions), optionally restrict Trusted Hosts to the machine that runs
this server, and copy the token shown once after saving.

From the CLI:

```
config system api-user
    edit "mcp-admin"
        set accprofile "super_admin"
        set vdom "root"
    next
end
execute api-user generate-key mcp-admin
```

## Configure

```bash
cp config/config.example.json config/config.json
```

`config/config.json` is ignored by git. Each key under `devices` is the `device_id`
the tools take:

```json
{
  "server": {
    "name": "fortigate-mcp-server",
    "allow_writes": false
  },
  "fortigate": {
    "devices": {
      "fgt-hq": {
        "host": "192.0.2.1",
        "port": 443,
        "api_token": "your-api-token",
        "vdom": "root",
        "verify_ssl": true,
        "timeout": 30
      },
      "fgt-branch": {
        "host": "198.51.100.1",
        "port": 443,
        "api_token": "your-api-token",
        "vdom": "root",
        "verify_ssl": true,
        "timeout": 30
      }
    }
  },
  "logging": {
    "level": "INFO",
    "console": true
  }
}
```

- `allow_writes` keeps the server read-only until you set it to `true` (or export
  `FORTIGATE_MCP_ALLOW_WRITES=1`). While it is `true`, every write and destructive tool
  runs for real, including on production units, so turn it on deliberately.
- Keep `verify_ssl` on. If the FortiGate still uses its factory self-signed
  certificate, install a certificate the client trusts (or add the FortiGate's CA to the
  system trust store) rather than disabling verification. The server logs a warning
  for every device that has verification turned off.
- `username`/`password` are accepted as a fallback, but an API token is the supported
  path.

## Run

### Claude Code

```bash
claude mcp add fortigate -s user \
  -e FORTIGATE_MCP_CONFIG=/absolute/path/fortigate-mcp/config/config.json \
  -- uv run --directory /absolute/path/fortigate-mcp python -m src.fortigate_mcp.server
```

Check with `claude mcp list`, then restart Claude Code. A `.mcp.json` example for
project scope is in `examples/claude_code_mcp.json`.

### Claude Desktop, Cursor

`examples/claude_desktop_config.stdio.json` and `examples/cursor_mcp_config.json`
contain ready-to-edit entries. The stdio server needs `FORTIGATE_MCP_CONFIG` in its
environment or `--config` on the command line.

### HTTP transport

```bash
./start_http_server.sh
# or
uv run python -m src.fortigate_mcp.server_http \
  --host 127.0.0.1 --port 8814 --path /fortigate-mcp --config config/config.json
```

The MCP endpoint is `http://127.0.0.1:8814/fortigate-mcp`; `GET /health` answers
without a token. Bind to anything other than `127.0.0.1` only after setting
`auth.require_auth` to `true` and listing bearer tokens under `auth.api_tokens`.
`HTTP_MCP_GUIDE.md` covers the HTTP mode in detail.

### Docker

```bash
docker-compose up -d
```

The compose file publishes the port on the loopback interface only.

## Safety model

Every tool carries a risk class that is checked at dispatch time, on both transports:

| Class | Count | Examples | Default |
|---|---|---|---|
| read | 111 | `list_*`, `get_*`, `query_*`, `lookup_*`, `cmdb_list`, `monitor_get`, `backup_config` | allowed |
| write | 19 | `create_*`, `update_*`, `add_*`, `move_firewall_policy`, `execute_*` | refused until writes are enabled |
| destructive | 10 | `delete_*`, `remove_*` | refused until writes are enabled |

The classification is derived from the tool name and verified by the test suite;
`SECURITY.md` lists every tool with its class. Secret-looking fields (passwords, PSKs,
passphrases, SNMP communities, keys) are redacted from every response, and the
device token never appears in logs or error messages.

`backup_config` is a read tool for the device, but it writes a file on the machine
running the server; it refuses to overwrite an existing file unless asked.

## Tool reference

### Devices

`list_devices`, `get_device_status`, `test_device_connection`, `add_device`,
`remove_device`, `discover_vdoms`, `health_check`, `get_server_info`,
`get_system_resources`, `get_performance_status`, `get_system_time`,
`list_firmware`, `get_license_status`, `get_ha_status`, `get_security_rating`,
`list_running_processes`

### Firewall policies

`list_firewall_policies`, `get_firewall_policy_detail` (resolves groups, identity
and profiles), `create_firewall_policy`, `update_firewall_policy`,
`move_firewall_policy`, `delete_firewall_policy`, `lookup_policy` (which rule would
match a given flow), `list_central_snat_rules`, `list_shaping_policies`,
`list_traffic_shapers`, `list_recurring_schedules`, `list_onetime_schedules`,
`list_internet_service_names`

### Objects

Addresses: `list_address_objects`, `create_address_object`, `update_address_object`,
`delete_address_object`.
Address groups: `list_address_groups`, `get_address_group_detail`,
`create_address_group`, `add_address_group_members`, `remove_address_group_members`,
`delete_address_group`.
Services: `list_service_objects`, `create_service_object`, `update_service_object`,
`delete_service_object`, `list_service_groups`.
VIPs and pools: `list_virtual_ips`, `get_virtual_ip_detail`, `create_virtual_ip`,
`update_virtual_ip`, `delete_virtual_ip`, `list_vip_groups`, `list_ip_pools`.

### Network and routing

`list_interfaces`, `get_interface_status`, `list_interface_counters`, `list_zones`,
`list_static_routes`, `get_static_route_detail`, `create_static_route`,
`update_static_route`, `delete_static_route`, `get_routing_table`,
`list_ipv6_routes`, `lookup_route`, `list_policy_routes`, `get_bgp_config`,
`get_ospf_config`, `list_prefix_lists`, `list_route_maps`, `get_sdwan_config`,
`list_sdwan_health_checks`, `list_sdwan_members`, `list_arp_table`,
`list_lldp_neighbors`, `ping_from_device`, `geoip_lookup`

### DHCP

`list_dhcp_servers` (with reservations), `list_dhcp_leases`,
`create_dhcp_reservation`, `delete_dhcp_reservation`

### VPN

`list_ipsec_tunnels` (live status), `list_ipsec_phase1`, `list_ipsec_phase2`,
`execute_ipsec_tunnel_action` (up/down), `list_ssl_vpn_sessions`,
`get_ssl_vpn_settings`, `list_ssl_vpn_portals`, `list_local_certificates`,
`list_ca_certificates`, `list_remote_certificates`

### Users and authentication

`list_local_users`, `list_user_groups`, `list_firewall_auth_sessions`,
`list_radius_servers`, `list_ldap_servers`, `list_tacacs_servers`,
`list_saml_servers`, `list_fsso_agents`, `list_fortitokens`, `list_admins`,
`list_api_users`, `list_endpoint_devices`

### Security profiles

`list_security_profiles` and `get_security_profile_detail` for `application`,
`webfilter`, `antivirus`, `ips`, `dnsfilter`, `ssl-ssh`, `dlp`, `emailfilter`,
`file-filter`, `icap`, `ssh-filter`, `waf`, `voip` and `virtual-patch`;
`list_url_filters`, `list_dns_domain_filters`, `list_ips_custom_signatures`,
`list_application_groups`

### Sessions and logs

`list_active_sessions`, `get_fortiview_top`, `query_traffic_log`,
`query_event_log`, `query_utm_log`, `get_log_settings`, `list_syslog_settings`,
`get_fortianalyzer_settings`, `backup_config`

### System settings

`get_system_global`, `get_dns_settings`, `get_ntp_settings`,
`list_snmp_communities`, `get_snmp_sysinfo`

### Wireless and switching

`list_wireless_ssids`, `list_ap_profiles`, `list_managed_aps`, `list_wifi_clients`,
`list_rogue_aps`, `get_wifi_controller_settings`, `list_managed_switches`,
`list_switch_port_stats`

### Generic access to the whole API

`cmdb_list`, `cmdb_get`, `create_cmdb_object`, `update_cmdb_object`,
`delete_cmdb_object`, `monitor_get`, `execute_monitor_action`, `log_get`

These take a FortiOS path and reach any table or monitor endpoint, for example:

```
cmdb_list   path="firewall/policy" filter_expr="action==deny" format_fields="policyid|name|srcaddr"
cmdb_get    path="system/interface" key="vlan10"
monitor_get path="system/interface" params={"interface_name": "wan"}
log_get     path="memory/event/vpn" rows=20 filter_expr="logdesc=@tunnel"
execute_monitor_action path="firewall/session/close" data={"saddr": "10.0.0.5", "daddr": "1.1.1.1", "sport": 51000, "dport": 443, "pro": "tcp"}
```

Paths are validated before they become URL segments; keys are percent-encoded, so
names with spaces such as `G Suite` work.

HTTP-only: `test_connection`, `health`, `get_schema_info`.

## Development

```bash
uv sync --locked --all-extras
uv run pytest                 # full suite with the coverage gate from pyproject.toml
uv run pytest -q --no-cov     # quicker iteration
uv run ruff check src tests
uv run mypy src
```

The tool surface is frozen in `tests/fixtures/tool_schemas_*.json`. After an
intentional schema change, regenerate the goldens and update the SHA pins in
`tests/test_engine_gate.py`:

```bash
UPDATE_SNAPSHOTS=1 uv run pytest tests/test_tool_schema_snapshot.py --no-cov
```

Adding a parameterless read tool is one `CatalogEntry` in
`src/fortigate_mcp/tools/catalog.py` plus a row in the `SECURITY.md` table.

## Project layout

```
src/fortigate_mcp/
  server.py            stdio entry point
  server_http.py       HTTP entry point (uvicorn + bearer-token middleware)
  registry.py          every tool, its description and risk class, for both transports
  core/fortigate.py    REST client (cmdb/monitor/log, typed endpoints, generic helpers)
  validation.py        path/key/host validators and secret redaction
  formatting/          text renderers for each resource type
  tools/               tool classes: device, firewall, network, routing, virtual_ip,
                       dhcp, security, vpn, users, system, generic, catalog
config/                config.example.json (copy to config.json)
examples/              MCP client configuration snippets
tests/                 pytest suite, respx-based API tests, golden tool schemas
```

## Troubleshooting

- `FORTIGATE_MCP_CONFIG environment variable must be set`: pass `-e` in
  `claude mcp add` or `--config` on the command line.
- `Authentication failed` / HTTP 401: wrong token, or the request comes from an
  address outside the API user's trusted hosts.
- `Permission denied` / HTTP 403 on a single tool: the API user's admin profile lacks
  that area (for example `list_firewall_auth_sessions` needs the user monitor
  permission).
- HTTP 404 on a catalog tool: that FortiOS release or model does not have the
  endpoint; `monitor_get`/`cmdb_list` with a nearby path usually finds the current one.
- A `*_tool is a write tool and this server is running in read-only mode` error means
  `allow_writes` is still `false`.
- Session-table and log filters use FortiOS filter syntax (`srcaddr==10.0.0.5`,
  `logdesc=@login`); the typed tools build these for you.

## Credits

This project builds on [alpadalar/fortigate-mcp-server](https://github.com/alpadalar/fortigate-mcp-server/).
Thank you for the repository: the configuration loader, the dual stdio/HTTP transport, the
read-only write gate and the test harness all come from there.

The purpose of this fork is to add tools. The original 33 tools covered devices, policies,
address and service objects, routes and VIPs; this repository adds address groups, DHCP,
VPN, identity, security profiles, sessions, logs, diagnostics, a catalog of read-only list
tools and generic access to the rest of the FortiOS REST API, for a total of 140 tools.

## License

MIT License, see `LICENSE`.

FortiGate and FortiOS are trademarks of Fortinet, Inc. This project is not affiliated
with Fortinet.
