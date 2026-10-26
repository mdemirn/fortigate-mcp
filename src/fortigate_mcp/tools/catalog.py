"""Declarative catalog of simple read-only tools.

Every entry below becomes an MCP tool with the signature
``(device_id, vdom=None)``: it GETs one cmdb or monitor endpoint and renders
the records compactly (secret-looking fields redacted). Adding a tool is one
line here plus a line in the SECURITY.md risk table.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from mcp.types import TextContent as Content

from ..formatting.templates import FortiGateTemplates
from ..validation import redact_sensitive_fields
from .base import FortiGateTool


@dataclass(frozen=True)
class CatalogEntry:
    name: str
    description: str
    section: str          # "cmdb" or "monitor"
    path: str
    title: str
    preferred: Tuple[str, ...] = ()
    params: Dict[str, Any] = field(default_factory=dict)
    empty_text: str = "No entries"


CATALOG: List[CatalogEntry] = [
    # --- system -----------------------------------------------------------
    CatalogEntry("get_system_global", "Show global system settings: hostname, admin ports/timeouts, timezone, management features.",
                 "cmdb", "system/global", "System Global Settings",
                 ("hostname", "alias", "admin-sport", "admin-port", "admin-ssh-port", "admintimeout", "timezone", "gui-theme", "admin-https-redirect")),
    CatalogEntry("get_dns_settings", "Show the system DNS configuration (primary/secondary servers, domain, DoT/DoH protocol).",
                 "cmdb", "system/dns", "System DNS Settings", ("primary", "secondary", "protocol", "domain", "dns-over-tls", "server-hostname")),
    CatalogEntry("get_ntp_settings", "Show the NTP configuration (sync mode, servers, server mode on interfaces).",
                 "cmdb", "system/ntp", "System NTP Settings", ("ntpsync", "type", "syncinterval", "server-mode", "ntpserver", "interface")),
    CatalogEntry("list_admins", "List administrator accounts with profile, trusted hosts and two-factor settings (passwords redacted).",
                 "cmdb", "system/admin", "Administrators", ("name", "accprofile", "trusthost1", "trusthost2", "two-factor", "remote-auth", "vdom", "comments")),
    CatalogEntry("list_api_users", "List REST API users (api-user) with their admin profile and trusted hosts (keys redacted).",
                 "cmdb", "system/api-user", "REST API Users", ("name", "accprofile", "vdom", "trusthost", "cors-allow-origin", "comments")),
    CatalogEntry("list_zones", "List interface zones and their member interfaces.",
                 "cmdb", "system/zone", "Zones", ("name", "interface", "intrazone", "description")),
    CatalogEntry("list_snmp_communities", "List SNMP v1/v2c communities and their hosts (community strings redacted).",
                 "cmdb", "system.snmp/community", "SNMP Communities", ("id", "name", "status", "hosts", "query-v1-status", "query-v2c-status", "trap-v2c-status")),
    CatalogEntry("get_snmp_sysinfo", "Show SNMP agent status, contact, location and description.",
                 "cmdb", "system.snmp/sysinfo", "SNMP System Info", ("status", "contact-info", "description", "location", "engine-id")),
    CatalogEntry("list_syslog_settings", "Show the primary syslog server settings (log.syslogd/setting).",
                 "cmdb", "log.syslogd/setting", "Syslog Settings", ("status", "server", "mode", "port", "facility", "enc-algorithm", "format", "source-ip")),
    CatalogEntry("get_fortianalyzer_settings", "Show FortiAnalyzer logging settings (log.fortianalyzer/setting).",
                 "cmdb", "log.fortianalyzer/setting", "FortiAnalyzer Settings", ("status", "server", "upload-option", "reliable", "enc-algorithm", "source-ip")),
    CatalogEntry("list_local_certificates", "List local (device) certificates with subject, issuer and validity (private keys redacted).",
                 "cmdb", "vpn.certificate/local", "Local Certificates", ("name", "range", "source", "comments", "ca-identifier", "auto-regenerate-days")),
    CatalogEntry("list_ca_certificates", "List trusted CA certificates installed on the device.",
                 "cmdb", "vpn.certificate/ca", "CA Certificates", ("name", "range", "source", "auto-update-days", "ca-identifier")),
    CatalogEntry("get_ha_status", "Show HA cluster statistics (members, roles, sync state). Standalone units return an empty list.",
                 "monitor", "system/ha-statistics", "HA Status", ("hostname", "serial_no", "is_root_primary", "sync_status", "priority", "cpu_usage", "mem_usage")),
    CatalogEntry("get_license_status", "Show FortiGuard/FortiCare license and subscription status.",
                 "monitor", "license/status", "License Status", ()),
    CatalogEntry("list_firmware", "Show the running firmware and available upgrade images (monitor/system/firmware).",
                 "monitor", "system/firmware", "Firmware", ("version", "build", "branch", "major", "minor", "patch", "release-type", "platform-id")),
    CatalogEntry("get_system_time", "Show the device clock and timezone (monitor/system/time).",
                 "monitor", "system/time", "System Time", ("time", "timezone", "hour", "minute")),
    CatalogEntry("get_performance_status", "Show CPU/memory/session/uptime performance counters (monitor/system/performance/status).",
                 "monitor", "system/performance/status", "Performance Status", ()),
    CatalogEntry("get_security_rating", "Show the Security Fabric security rating summary (monitor/system/security-rating).",
                 "monitor", "system/security-rating", "Security Rating", ()),
    CatalogEntry("list_running_processes", "List running processes with CPU/memory usage (monitor/system/running-processes).",
                 "monitor", "system/running-processes", "Running Processes", ("pid", "cmd", "cpu", "mem", "state")),
    # --- firewall objects ------------------------------------------------
    CatalogEntry("list_ip_pools", "List NAT IP pools (type, start/end IP, ARP reply).",
                 "cmdb", "firewall/ippool", "IP Pools", ("name", "type", "startip", "endip", "arp-reply", "comments")),
    CatalogEntry("list_vip_groups", "List virtual IP groups and their member VIPs.",
                 "cmdb", "firewall/vipgrp", "VIP Groups", ("name", "interface", "member", "comments")),
    CatalogEntry("list_recurring_schedules", "List recurring firewall schedules (days and time window).",
                 "cmdb", "firewall.schedule/recurring", "Recurring Schedules", ("name", "day", "start", "end", "color")),
    CatalogEntry("list_onetime_schedules", "List one-time firewall schedules (start/end datetime).",
                 "cmdb", "firewall.schedule/onetime", "One-time Schedules", ("name", "start", "end", "expiration-days")),
    CatalogEntry("list_central_snat_rules", "List central SNAT map rules.",
                 "cmdb", "firewall/central-snat-map", "Central SNAT Rules", ("policyid", "status", "srcintf", "dstintf", "orig-addr", "dst-addr", "nat-ippool", "protocol", "comments")),
    CatalogEntry("list_traffic_shapers", "List shared traffic shapers (guaranteed/maximum bandwidth, priority).",
                 "cmdb", "firewall.shaper/traffic-shaper", "Traffic Shapers", ("name", "guaranteed-bandwidth", "maximum-bandwidth", "bandwidth-unit", "priority", "per-policy")),
    CatalogEntry("list_shaping_policies", "List traffic shaping policies.",
                 "cmdb", "firewall/shaping-policy", "Shaping Policies", ("id", "name", "status", "srcintf", "dstintf", "srcaddr", "dstaddr", "service", "traffic-shaper", "traffic-shaper-reverse", "comment")),
    CatalogEntry("list_internet_service_names", "List FortiGuard Internet Service names that policies can reference (large list; use cmdb_list with a filter for lookups).",
                 "cmdb", "firewall/internet-service-name", "Internet Service Names", ("name", "type", "internet-service-id", "country-id", "region-id", "city-id")),
    # --- routing -----------------------------------------------------------
    CatalogEntry("list_policy_routes", "List policy-based routes (router/policy).",
                 "cmdb", "router/policy", "Policy Routes", ("seq-num", "status", "input-device", "src", "dst", "protocol", "gateway", "output-device", "action", "comments")),
    CatalogEntry("get_bgp_config", "Show the BGP configuration (AS, router-id, neighbors, networks).",
                 "cmdb", "router/bgp", "BGP Configuration", ("as", "router-id", "neighbor", "network", "redistribute")),
    CatalogEntry("get_ospf_config", "Show the OSPF configuration (router-id, areas, networks, interfaces).",
                 "cmdb", "router/ospf", "OSPF Configuration", ("router-id", "area", "network", "ospf-interface", "redistribute")),
    CatalogEntry("list_prefix_lists", "List router prefix lists.",
                 "cmdb", "router/prefix-list", "Prefix Lists", ("name", "rule", "comments")),
    CatalogEntry("list_route_maps", "List router route maps.",
                 "cmdb", "router/route-map", "Route Maps", ("name", "rule", "comments")),
    CatalogEntry("get_sdwan_config", "Show the SD-WAN configuration (zones, members, health checks, rules).",
                 "cmdb", "system/sdwan", "SD-WAN Configuration", ("status", "load-balance-mode", "zone", "members", "health-check", "service")),
    CatalogEntry("list_sdwan_health_checks", "Show SD-WAN health-check results per member (latency, jitter, packet loss).",
                 "monitor", "virtual-wan/health-check", "SD-WAN Health Checks", ()),
    CatalogEntry("list_sdwan_members", "Show SD-WAN member interface status and traffic.",
                 "monitor", "virtual-wan/members", "SD-WAN Members", ()),
    CatalogEntry("list_ipv6_routes", "Show the IPv6 routing table (monitor/router/ipv6).",
                 "monitor", "router/ipv6", "IPv6 Routing Table", ("ip_mask", "gateway", "interface", "type", "distance", "metric")),
    # --- vpn configuration --------------------------------------------------
    CatalogEntry("list_ipsec_phase1", "List IPsec phase-1 interfaces: type, remote gateway, IKE version, proposals, peer settings (PSKs redacted).",
                 "cmdb", "vpn.ipsec/phase1-interface", "IPsec Phase 1 Interfaces",
                 ("name", "type", "interface", "ike-version", "remote-gw", "peertype", "net-device", "mode-cfg", "proposal", "dhgrp", "comments")),
    CatalogEntry("list_ipsec_phase2", "List IPsec phase-2 selectors: phase-1 name, local/remote subnets, proposals, auto-negotiate.",
                 "cmdb", "vpn.ipsec/phase2-interface", "IPsec Phase 2 Interfaces",
                 ("name", "phase1name", "src-subnet", "dst-subnet", "src-name", "dst-name", "proposal", "dhgrp", "auto-negotiate", "keylifeseconds", "comments")),
    CatalogEntry("get_ssl_vpn_settings", "Show SSL-VPN settings (status, port, source interfaces, portal mapping, tunnel IP pools).",
                 "cmdb", "vpn.ssl/settings", "SSL-VPN Settings", ("status", "port", "source-interface", "source-address", "default-portal", "authentication-rule", "tunnel-ip-pools", "dns-server1", "servercert")),
    CatalogEntry("list_ssl_vpn_portals", "List SSL-VPN portals (tunnel mode, split tunneling, IP pools, web mode).",
                 "cmdb", "vpn.ssl.web/portal", "SSL-VPN Portals", ("name", "tunnel-mode", "web-mode", "split-tunneling", "split-tunneling-routing-address", "ip-pools", "dns-server1", "forticlient-download")),
    CatalogEntry("list_remote_certificates", "List remote certificates (vpn.certificate/remote).",
                 "cmdb", "vpn.certificate/remote", "Remote Certificates", ("name", "range", "source")),
    # --- user / authentication servers ---------------------------------------
    CatalogEntry("list_radius_servers", "List RADIUS servers (addresses, auth type, NAS IP; secrets redacted).",
                 "cmdb", "user/radius", "RADIUS Servers", ("name", "server", "secondary-server", "auth-type", "nas-ip", "radius-port", "timeout", "source-ip")),
    CatalogEntry("list_ldap_servers", "List LDAP servers (server, port, DN, bind type, secure mode; passwords redacted).",
                 "cmdb", "user/ldap", "LDAP Servers", ("name", "server", "secondary-server", "port", "cnid", "dn", "type", "username", "secure", "group-member-check")),
    CatalogEntry("list_tacacs_servers", "List TACACS+ servers (secrets redacted).",
                 "cmdb", "user/tacacs+", "TACACS+ Servers", ("name", "server", "secondary-server", "port", "authen-type", "authorization", "source-ip")),
    CatalogEntry("list_saml_servers", "List SAML identity providers (entity IDs, SSO/SLO URLs).",
                 "cmdb", "user/saml", "SAML Servers", ("name", "entity-id", "idp-entity-id", "single-sign-on-url", "single-logout-url", "user-name", "group-name")),
    CatalogEntry("list_fsso_agents", "List FSSO collector agents (passwords redacted).",
                 "cmdb", "user/fsso", "FSSO Agents", ("name", "type", "server", "port", "server2", "ldap-server", "source-ip")),
    CatalogEntry("list_fortitokens", "List FortiTokens and their status/assignment (monitor/user/fortitoken).",
                 "monitor", "user/fortitoken", "FortiTokens", ("serial", "status", "type", "user", "license")),
    CatalogEntry("list_endpoint_devices", "List devices seen by the device inventory (monitor/user/device/query): IP, MAC, hostname, OS, interface.",
                 "monitor", "user/device/query", "Detected Devices", ("ipv4_address", "mac", "hostname", "os_name", "os_version", "hardware_type", "hardware_vendor", "detected_interface", "last_seen"),
                 {"number": 500}),
    # --- network monitor -------------------------------------------------------
    CatalogEntry("list_arp_table", "Show the ARP table (IP, MAC, interface, age).",
                 "monitor", "network/arp", "ARP Table", ("ip", "mac", "interface", "age")),
    CatalogEntry("list_lldp_neighbors", "Show LLDP neighbors (switch ports, neighbor system names).",
                 "monitor", "network/lldp/neighbors", "LLDP Neighbors", ("local_port", "system_name", "port_id", "port_description", "chassis_id", "management_ip")),
    CatalogEntry("list_managed_switches", "List FortiSwitch units managed by the switch controller (monitor/switch-controller/managed-switch).",
                 "monitor", "switch-controller/managed-switch", "Managed Switches", ("name", "serial", "state", "status", "os_version", "connecting_from", "ports")),
    CatalogEntry("list_switch_port_stats", "Show FortiSwitch port statistics (monitor/switch-controller/port-stats).",
                 "monitor", "switch-controller/port-stats", "Switch Port Statistics", ()),
    CatalogEntry("list_interface_counters", "Show per-interface traffic counters and link state (monitor/system/interface).",
                 "monitor", "system/interface", "Interface Counters", ("name", "link", "speed", "duplex", "rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_errors", "tx_errors")),
    # --- wireless -----------------------------------------------------------
    CatalogEntry("list_wireless_ssids", "List SSIDs (wireless-controller/vap): security mode, VLAN, broadcast, schedule (passphrases redacted).",
                 "cmdb", "wireless-controller/vap", "Wireless SSIDs (VAPs)", ("name", "ssid", "security", "encrypt", "vlanid", "broadcast-ssid", "schedule", "local-bridging", "comment")),
    CatalogEntry("list_ap_profiles", "List FortiAP profiles (platform, radios, SSIDs per radio).",
                 "cmdb", "wireless-controller/wtp-profile", "AP Profiles", ("name", "platform", "radio-1", "radio-2", "comment")),
    CatalogEntry("list_managed_aps", "Show managed FortiAPs with status, IP, clients and firmware (monitor/wifi/managed_ap).",
                 "monitor", "wifi/managed_ap", "Managed Access Points", ("name", "serial", "status", "state", "connecting_from", "local_ipv4_addr", "clients", "os_version", "wtp_profile", "ap_profile")),
    CatalogEntry("list_wifi_clients", "Show connected Wi-Fi clients (SSID, MAC, IP, signal, AP).",
                 "monitor", "wifi/client", "Wi-Fi Clients", ("hostname", "ip", "mac", "ssid", "wtp_name", "signal", "data_rate_bps", "association_time", "security", "vlan_id")),
    CatalogEntry("list_rogue_aps", "Show detected rogue/neighbor access points (monitor/wifi/rogue_ap).",
                 "monitor", "wifi/rogue_ap", "Rogue Access Points", ("ssid", "bssid", "channel", "signal_strength", "is_rogue", "first_seen", "last_seen", "detected_by")),
    CatalogEntry("get_wifi_controller_settings", "Show wireless controller settings (country, duplicate SSID handling, fake SSID action).",
                 "cmdb", "wireless-controller/setting", "Wireless Controller Settings", ("country", "duplicate-ssid", "fake-ssid-action", "wfa-compatibility")),
    # --- security profile side tables ---------------------------------------
    CatalogEntry("list_url_filters", "List static URL filter tables used by web filter profiles (entries with action).",
                 "cmdb", "webfilter/urlfilter", "URL Filter Tables", ("id", "name", "comment", "entries")),
    CatalogEntry("list_dns_domain_filters", "List DNS filter domain lists (dnsfilter/domain-filter).",
                 "cmdb", "dnsfilter/domain-filter", "DNS Domain Filters", ("id", "name", "comment", "entries")),
    CatalogEntry("list_ips_custom_signatures", "List custom IPS signatures (ips/custom).",
                 "cmdb", "ips/custom", "Custom IPS Signatures", ("tag", "severity", "status", "action", "log", "comment")),
    CatalogEntry("list_application_groups", "List application control groups (application/group).",
                 "cmdb", "application/group", "Application Groups", ("name", "type", "application", "category", "comment")),
]

CATALOG_BY_NAME: Dict[str, CatalogEntry] = {entry.name: entry for entry in CATALOG}


class CatalogTools(FortiGateTool):
    """Executes catalog entries: one GET, one compact rendering."""

    def run(self, name: str, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        entry = CATALOG_BY_NAME.get(name)
        if entry is None:
            raise ValueError(f"Unknown catalog tool: {self._safe_id(name)}")
        operation = name.replace("_", " ")
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            if entry.section == "cmdb":
                data = api_client.cmdb_list(entry.path, params=dict(entry.params) or None, vdom=vdom)
            else:
                data = api_client.monitor_get(entry.path, params=dict(entry.params) or None, vdom=vdom)
            safe = redact_sensitive_fields(data)
            text = FortiGateTemplates._generic_records(entry.title, safe, list(entry.preferred), entry.empty_text)
            return [Content(type="text", text=text)]
        except Exception as e:
            return self._handle_error(operation, device_id, e)

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for catalog tools."""
        return {
            "name": "catalog_tools",
            "description": "Read-only FortiOS cmdb/monitor list tools",
            "operations": [
                {"name": entry.name, "description": entry.description,
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "vdom", "type": "string", "required": False}]}
                for entry in CATALOG
            ],
        }
