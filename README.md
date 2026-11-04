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

**Contents:** [Requirements](#requirements) ·
[Installation](#installation) ·
[Connect your MCP client](#6-connect-your-mcp-client) ·
[HTTP transport](#http-transport) · [Docker](#docker) ·
[Safety model](#safety-model) · [Tool reference](#tool-reference) ·
[Troubleshooting](#troubleshooting)

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

- A machine that reaches the FortiGate management interface over HTTPS (TCP 443 or
  your admin port)
- Python 3.11 to 3.13. 3.12 is pinned in `.python-version` and recommended; 3.14 is not
  supported yet because `pydantic-core 2.33` ships no wheel for it
- [`uv`](https://docs.astral.sh/uv/) (recommended) or `pip`, and Git
- FortiOS 7.4, 7.6 or 8.0, with a REST API admin and its API token
- An MCP client that speaks stdio or streamable HTTP: Claude Code, Claude Desktop,
  Cursor or another
- Optional: Docker with Compose v2 for the container deployment, Node.js for
  `mcp-remote` (Claude Desktop over HTTP), Node.js for the MCP Inspector check

## Installation

The steps below take you from an empty machine to an assistant that can query your
FortiGate:

1. Install `uv`
2. Get the code and install the dependencies
3. Create a REST API admin on the FortiGate
4. Write `config/config.json`
5. Check the server
6. Connect your MCP client
7. Send the first requests, and enable writes when you need them

### 1. Install uv

macOS and Linux:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

macOS with Homebrew: `brew install uv`. Windows (PowerShell):

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Open a new terminal and check with `uv --version`.

### 2. Get the code and install the dependencies

```bash
git clone https://github.com/mdemirn/fortigate-mcp.git
cd fortigate-mcp
uv sync --locked
uv run fortigate-mcp-server --version    # prints: fortigate-mcp-server 1.1.0
pwd                                      # note this absolute path for the client configs
```

`uv sync --locked` creates `.venv`, downloads Python 3.12 if the machine does not have
it, and installs the exact versions recorded in `uv.lock`.

Without `uv`:

```bash
python3.12 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e .
fortigate-mcp-server --version
```

`pip` resolves the version ranges in `pyproject.toml` instead of the lock file. In the
client configs below, use `/absolute/path/fortigate-mcp/.venv/bin/fortigate-mcp-server`
(Windows: `.venv\Scripts\fortigate-mcp-server.exe`) as the command instead of `uv run`.

### 3. Create a REST API admin on the FortiGate

In the GUI: System > Administrators > Create New > REST API Admin. Pick an admin
profile, restrict Trusted Hosts to the machine that runs this server, and copy the
token shown once after saving.

From the CLI, a read-only profile and an API user limited to the MCP host:

```
config system accprofile
    edit "mcp-read"
        set comments "FortiGate MCP server, read-only"
        set secfabgrp read
        set ftviewgrp read
        set authgrp read
        set sysgrp read
        set netgrp read
        set loggrp read
        set fwgrp read
        set vpngrp read
        set utmgrp read
        set wanoptgrp read
        set wifi read
    next
end
config system api-user
    edit "mcp-api"
        set comments "FortiGate MCP server"
        set accprofile "mcp-read"
        set vdom "root"
        config trusthost
            edit 1
                set ipv4-trusthost <mcp-host-ip> 255.255.255.255
            next
        end
    next
end
execute api-user generate-key mcp-api
```

- The read profile is enough for every read tool. For write tools, change `read` to
  `read-write` on the areas the assistant may change (for example `fwgrp` for
  policies and objects, `netgrp` for interfaces, routes and DHCP), or use the built-in
  `super_admin` profile, which allows everything.
- Set `vdom` to the VDOM the token should work in; on a multi-VDOM unit, create one API
  user per VDOM or use one with access to all of them.
- If the server reaches the FortiGate through NAT, the trusted host is the address the
  FortiGate sees.

Test the token from the machine that will run the server:

```bash
curl -H "Authorization: Bearer <api-token>" https://<fortigate-address>/api/v2/monitor/system/status
```

A JSON answer with `"status": "success"` means the token and the trusted host are
right. A certificate error means the FortiGate presents a certificate this machine does
not trust; fix that before step 4 (see `verify_ssl` below).

### 4. Write the configuration

```bash
cp config/config.example.json config/config.json
chmod 600 config/config.json        # the file holds API tokens
```

`config/config.json` is ignored by git. Replace the two sample devices in the copied
file with your own. Each key under `devices` is the `device_id` the tools take:

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

| Key | Meaning |
|---|---|
| `server.allow_writes` | `false` keeps every write and destructive tool disabled (default) |
| `fortigate.devices.<id>.host` | IP address or hostname of the FortiGate management interface |
| `port` | HTTPS admin port, `443` unless you changed `admin-sport` |
| `api_token` | The key from step 3 |
| `vdom` | VDOM the requests go to |
| `verify_ssl` | Verify the FortiGate certificate; keep it `true` |
| `timeout` | Seconds per API request |
| `auth.require_auth`, `auth.api_tokens` | Bearer-token protection for the HTTP transport only |
| `logging.level`, `logging.console`, `logging.file` | Log level, stderr logging, optional rotating log file |

- `allow_writes` keeps the server read-only until you set it to `true` (or export
  `FORTIGATE_MCP_ALLOW_WRITES=1`). The environment variable can only turn writes on:
  `FORTIGATE_MCP_ALLOW_WRITES=0` does not override `"allow_writes": true`. While writes
  are on, every write and destructive tool runs for real, including on production
  units, so turn it on deliberately.
- Keep `verify_ssl` on. If the FortiGate still uses its factory self-signed
  certificate, install a certificate the client trusts (or add the FortiGate's CA to the
  system trust store) rather than disabling verification. The server logs a warning
  for every device that has verification turned off.
- `logging.file` is resolved from the server's working directory. `uv run --directory`
  starts the server in the repository, so `logs/fortigate_mcp.log` lands there; with
  any other launcher, use an absolute path or leave the key out. Console logging goes
  to stderr and never interferes with the stdio protocol.
- `username`/`password` are accepted as a fallback, but an API token is the supported
  path.
- The configuration is read at startup. Restart the server (or reconnect it in the
  client) after every change.

### 5. Check the server

The [MCP Inspector](https://github.com/modelcontextprotocol/inspector) starts the server
the same way a client does and lets you call tools from a browser:

```bash
npx @modelcontextprotocol/inspector \
  -e FORTIGATE_MCP_CONFIG="$PWD/config/config.json" \
  -- uv run --directory "$PWD" fortigate-mcp-server
```

Click **Connect**, open **Tools**, run `list_devices`, then `test_device_connection` with
one of your device IDs. The stdio server lists 137 tools.

### 6. Connect your MCP client

In every example, replace `/absolute/path/fortigate-mcp` with the path printed by `pwd`
in step 2.

#### Claude Code

```bash
claude mcp add fortigate -s user \
  -e FORTIGATE_MCP_CONFIG=/absolute/path/fortigate-mcp/config/config.json \
  -- uv run --directory /absolute/path/fortigate-mcp fortigate-mcp-server
claude mcp list
```

`-s user` makes the server available in every project; `-s project` writes it to the
project's `.mcp.json` instead (`examples/claude_code_mcp.json` shows that format). Only
the config path goes into `.mcp.json`; the tokens stay in `config/config.json`. Start a
new Claude Code session and run `/mcp` to see the server and its tools.

To use a running HTTP server (see [HTTP transport](#http-transport)) instead:

```bash
claude mcp add --transport http fortigate http://127.0.0.1:8814/fortigate-mcp
# with auth.require_auth = true
claude mcp add --transport http fortigate http://127.0.0.1:8814/fortigate-mcp \
  --header "Authorization: Bearer <http-token>"
```

#### Claude Desktop

Open Settings > Developer > Edit Config, or edit the file directly:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "fortigate": {
      "command": "/absolute/path/to/uv",
      "args": ["run", "--directory", "/absolute/path/fortigate-mcp", "fortigate-mcp-server"],
      "env": {
        "FORTIGATE_MCP_CONFIG": "/absolute/path/fortigate-mcp/config/config.json"
      }
    }
  }
}
```

- Claude Desktop does not read your shell `PATH`, so give the full path of `uv`
  (`which uv`, for example `/opt/homebrew/bin/uv` or `~/.local/bin/uv` written out in
  full; on Windows `where uv`).
- On Windows, write paths with forward slashes or doubled backslashes
  (`C:\\Users\\me\\fortigate-mcp`).
- Quit Claude Desktop completely before editing the file and start it again afterwards;
  the app can rewrite the file while it runs. The server then shows up in the tools
  menu of a new chat.
- For the HTTP transport, `examples/claude_desktop_config.http.json` bridges to the URL
  with `mcp-remote` (needs Node.js).

#### Cursor

Add the server to `~/.cursor/mcp.json` (all projects) or `.cursor/mcp.json` (one
project), then check Cursor Settings > MCP:

```json
{
  "mcpServers": {
    "fortigate": {
      "command": "uv",
      "args": ["run", "--directory", "/absolute/path/fortigate-mcp", "fortigate-mcp-server"],
      "env": {
        "FORTIGATE_MCP_CONFIG": "/absolute/path/fortigate-mcp/config/config.json"
      }
    }
  }
}
```

For a running HTTP server, use `"url": "http://127.0.0.1:8814/fortigate-mcp"` instead of
`command`/`args`/`env`; `examples/cursor_mcp_config.json` shows both forms.

#### Other clients

- stdio: command `uv`, arguments `run --directory /absolute/path/fortigate-mcp
  fortigate-mcp-server`, environment `FORTIGATE_MCP_CONFIG=/absolute/path/fortigate-mcp/config/config.json`
  (or `--config <path>` as an argument instead of the variable).
- Streamable HTTP: `http://127.0.0.1:8814/fortigate-mcp`, with an
  `Authorization: Bearer <token>` header when `auth.require_auth` is on.

`python -m src.fortigate_mcp.server` is equivalent to the `fortigate-mcp-server`
command and is what the files in `examples/` use.

### 7. First requests and enabling writes

Ask the assistant, for example:

- "List my FortiGate devices and test the connection to fgt-hq."
- "Show the firewall policies on fgt-hq that allow traffic to the internet."

When you want the assistant to change configuration:

1. Give the API user a profile with write access (step 3).
2. Set `"allow_writes": true` in `config/config.json` and restart the server.
3. Ask for a backup first ("Save a config backup of fgt-hq"), then for the change.
4. Set `allow_writes` back to `false` when you are done.

### HTTP transport

The HTTP transport serves several clients from one long-running process:

```bash
./start_http_server.sh
# or
uv run python -m src.fortigate_mcp.server_http \
  --host 127.0.0.1 --port 8814 --path /fortigate-mcp --config config/config.json
```

`start_http_server.sh` reads `MCP_HTTP_HOST`, `MCP_HTTP_PORT`, `MCP_HTTP_PATH` and
`FORTIGATE_MCP_CONFIG`, and uses `.venv` when it exists. Check it with:

```bash
curl http://127.0.0.1:8814/health        # {"status":"healthy"}
```

The MCP endpoint is `http://127.0.0.1:8814/fortigate-mcp` and lists 138 tools.
`GET /health` answers without a token. Before binding to anything other than
`127.0.0.1`, turn on bearer-token authentication:

```json
"auth": {
  "require_auth": true,
  "api_tokens": ["<output of: openssl rand -hex 32>"]
}
```

Clients then send `Authorization: Bearer <token>`. Put a TLS reverse proxy in front of
the server if clients connect over the network. `HTTP_MCP_GUIDE.md` covers the HTTP
mode in more detail.

### Docker

```bash
cp config/config.example.json config/config.json    # edit it as in step 4
docker compose up -d --build
docker compose logs -f
curl http://127.0.0.1:8814/health
```

The container runs the HTTP transport on port 8814, published on the loopback interface
only. `config/config.json` is mounted read-only and logs are written to `./logs`. Connect
clients to `http://127.0.0.1:8814/fortigate-mcp` as described in step 6. The FortiGate
addresses in the configuration must be reachable from the container.

### Updating

```bash
cd /absolute/path/fortigate-mcp
git pull
uv sync --locked
```

Then restart the MCP client, or run `docker compose up -d --build` for the container.

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
- `uv sync` tries to build `pydantic-core` and fails: uv picked Python 3.14. Run
  `uv sync --locked --python 3.12`.
- Claude Desktop shows the server as failed or disconnected right after start: the
  `command` is not found. Use the full path of `uv`, and check the app's MCP log
  (macOS: `~/Library/Logs/Claude/mcp-server-fortigate.log`).
- Tools do not appear after a config change: restart the server or the client; the
  configuration is read only at startup.
- `CERTIFICATE_VERIFY_FAILED`: the FortiGate certificate is not trusted on the machine
  running the server. Install a trusted certificate on the FortiGate or add its CA to
  the system trust store; see `verify_ssl` in step 4.
- A `RuntimeWarning: 'src.fortigate_mcp.server' found in sys.modules` line when the
  server is started with `python -m`: harmless; the `fortigate-mcp-server` command does
  not print it.
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
