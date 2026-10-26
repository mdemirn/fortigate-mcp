"""Tests for the extended tool surface: address groups, object maintenance,
policy ordering, DHCP, security profiles, VPN, users and system monitoring.

Tools-layer tests use a MagicMock(spec=FortiGateAPI) device so no socket is
ever touched; API-layer tests use respx against the real httpx request path.
"""
import json
from unittest.mock import MagicMock

import httpx
import pytest
import respx

from src.fortigate_mcp.config.models import AuthConfig, FortiGateDeviceConfig
from src.fortigate_mcp.core.fortigate import FortiGateAPI, FortiGateManager
from src.fortigate_mcp.formatting.templates import FortiGateTemplates
from src.fortigate_mcp.tools.dhcp import DhcpTools, normalize_mac, validate_ipv4
from src.fortigate_mcp.tools.firewall import FirewallTools
from src.fortigate_mcp.tools.network import NetworkTools
from src.fortigate_mcp.tools.security import SecurityProfileTools
from src.fortigate_mcp.tools.system import SystemTools
from src.fortigate_mcp.tools.users import UserTools
from src.fortigate_mcp.tools.vpn import VpnTools


def _manager_with_mock():
    manager = FortiGateManager({}, AuthConfig(require_auth=False, api_tokens=[], allowed_origins=["*"]))
    api = MagicMock(spec=FortiGateAPI)
    api.device_id = "dev"
    manager.devices["dev"] = api
    return manager, api


GROUPS = {"results": [
    {"name": "grp-allowed", "member": [{"name": "host-a"}, {"name": "host-b"}], "comment": "c"},
    {"name": "G Suite", "member": [{"name": "gmail.com"}]},
]}
ADDRS = {"results": [
    {"name": "host-a", "type": "ipmask", "subnet": "10.0.0.1 255.255.255.255"},
    {"name": "host-b", "type": "iprange", "start-ip": "10.0.0.2", "end-ip": "10.0.0.3"},
    {"name": "gmail.com", "type": "fqdn", "fqdn": "gmail.com"},
]}


# --- address groups ---------------------------------------------------------

class TestAddressGroups:
    def setup_method(self):
        self.manager, self.api = _manager_with_mock()
        self.tools = NetworkTools(self.manager)
        self.api.get_address_groups.return_value = json.loads(json.dumps(GROUPS))
        self.api.get_address_objects.return_value = ADDRS

    def test_list_groups_shows_members(self):
        text = self.tools.list_address_groups("dev")[0].text
        assert "grp-allowed (2 members)" in text and "host-a, host-b" in text

    def test_detail_resolves_members_without_path_lookup(self):
        text = self.tools.get_address_group_detail("dev", "G Suite")[0].text
        assert "fqdn gmail.com" in text
        self.api.get_address_objects.assert_called_once()

    def test_detail_unknown_group_is_error(self):
        text = self.tools.get_address_group_detail("dev", "nope")[0].text
        assert "Error" in text and "not found" in text.lower()

    def test_add_members_keeps_existing_and_skips_duplicates(self):
        text = self.tools.add_address_group_members("dev", "grp-allowed", ["host-b", "host-c"])[0].text
        assert "Added host-c" in text
        name, payload = self.api.update_address_group.call_args.args[:2]
        assert name == "grp-allowed"
        assert [m["name"] for m in payload["member"]] == ["host-a", "host-b", "host-c"]

    def test_add_members_noop_when_all_present(self):
        text = self.tools.add_address_group_members("dev", "grp-allowed", ["host-a"])[0].text
        assert "already contains" in text
        self.api.update_address_group.assert_not_called()

    def test_remove_members_refuses_to_empty_group(self):
        text = self.tools.remove_address_group_members("dev", "grp-allowed", ["host-a", "host-b"])[0].text
        assert "Error" in text and "at least one member" in text
        self.api.update_address_group.assert_not_called()

    def test_remove_members_updates_remaining(self):
        text = self.tools.remove_address_group_members("dev", "grp-allowed", ["host-a"])[0].text
        assert "Removed host-a" in text
        payload = self.api.update_address_group.call_args.args[1]
        assert [m["name"] for m in payload["member"]] == ["host-b"]

    def test_create_group_requires_members(self):
        text = self.tools.create_address_group("dev", "g", [])[0].text
        assert "Error" in text
        self.api.create_address_group.assert_not_called()

    def test_create_group_payload(self):
        self.tools.create_address_group("dev", "g", ["host-a"], comment="x")
        payload = self.api.create_address_group.call_args.args[0]
        assert payload == {"name": "g", "member": [{"name": "host-a"}], "comment": "x"}

    def test_delete_group_and_objects(self):
        assert "deleted" in self.tools.delete_address_group("dev", "g")[0].text
        assert "deleted" in self.tools.delete_address_object("dev", "host-a")[0].text
        assert "deleted" in self.tools.delete_service_object("dev", "svc")[0].text
        assert "updated" in self.tools.update_address_object("dev", "host-a", {"comment": "x"})[0].text
        assert "updated" in self.tools.update_service_object("dev", "svc", {"tcp-portrange": "1"})[0].text

    def test_list_service_groups_resolves_ports(self):
        self.api.get_service_groups.return_value = {"results": [{"name": "AD", "member": [{"name": "LDAP"}, {"name": "X"}]}]}
        self.api.get_service_objects.return_value = {"results": [{"name": "LDAP", "protocol": "TCP/UDP", "tcp-portrange": "389"}]}
        text = self.tools.list_service_groups("dev")[0].text
        assert "LDAP: TCP 389" in text and "X: Not resolved" in text


# --- firewall: move + group-aware detail ------------------------------------

class TestFirewallExtended:
    def setup_method(self):
        self.manager, self.api = _manager_with_mock()
        self.tools = FirewallTools(self.manager)

    def test_move_policy_calls_api(self):
        text = self.tools.move_policy("dev", "60", "before", "55")[0].text
        assert "moved before policy 55" in text
        self.api.move_firewall_policy.assert_called_once_with("60", "before", "55", vdom=None)

    def test_move_policy_rejects_same_id(self):
        text = self.tools.move_policy("dev", "60", "before", "60")[0].text
        assert "Error" in text
        self.api.move_firewall_policy.assert_not_called()

    def test_detail_expands_groups_identity_and_profiles(self):
        self.api.get_firewall_policy_detail.return_value = {"results": [{
            "policyid": 56, "name": "p", "status": "enable", "action": "accept",
            "srcintf": [{"name": "lan"}], "dstintf": [{"name": "wan"}],
            "srcaddr": [{"name": "grp-allowed"}], "dstaddr": [{"name": "all"}],
            "service": [{"name": "AD"}], "users": [{"name": "alice"}], "groups": [],
            "application-list": "app-x", "webfilter-profile": "", "utm-status": "enable",
            "nat": "enable", "ippool": "enable", "poolname": [{"name": "pool1"}],
        }]}
        self.api.get_address_objects.return_value = ADDRS
        self.api.get_service_objects.return_value = {"results": [{"name": "LDAP", "protocol": "TCP", "tcp-portrange": "389"}]}
        self.api.get_address_groups.return_value = GROUPS
        self.api.get_service_groups.return_value = {"results": [{"name": "AD", "member": [{"name": "LDAP"}]}]}
        text = self.tools.get_policy_detail("dev", "56")[0].text
        assert "grp-allowed: address group (2 members)" in text
        assert "host-a: 10.0.0.1 255.255.255.255" in text
        assert "AD: service group (1 members)" in text and "LDAP: TCP 389" in text
        assert "Identity (authentication required)" in text and "Users: alice" in text
        assert "Application Control: app-x" in text and "NAT IP Pool: pool1" in text

    def test_detail_survives_group_lookup_failure(self):
        self.api.get_firewall_policy_detail.return_value = {"results": {"policyid": 1, "name": "p", "srcaddr": [], "dstaddr": [], "service": [], "action": "deny"}}
        self.api.get_address_objects.side_effect = RuntimeError("boom")
        self.api.get_service_objects.side_effect = RuntimeError("boom")
        self.api.get_address_groups.side_effect = RuntimeError("boom")
        self.api.get_service_groups.side_effect = RuntimeError("boom")
        text = self.tools.get_policy_detail("dev", "1")[0].text
        assert "Policy Detail" in text and "DENY" in text


# --- DHCP -------------------------------------------------------------------

SERVERS = {"results": [
    {"id": 1, "interface": "lan", "status": "enable", "default-gateway": "192.168.1.1", "netmask": "255.255.255.0",
     "ip-range": [{"start-ip": "192.168.1.100", "end-ip": "192.168.1.200"}], "reserved-address": []},
    {"id": 6, "interface": "vlan10", "status": "enable", "default-gateway": "10.0.0.1", "netmask": "255.255.252.0",
     "ip-range": [{"start-ip": "10.0.0.50", "end-ip": "10.0.3.250"}],
     "reserved-address": [{"id": 3, "ip": "10.0.0.53", "mac": "02:00:00:00:00:53", "action": "reserved", "description": "printer"}]},
]}


class TestDhcpTools:
    def setup_method(self):
        self.manager, self.api = _manager_with_mock()
        self.tools = DhcpTools(self.manager)
        self.api.get_dhcp_servers.return_value = json.loads(json.dumps(SERVERS))

    def test_mac_and_ip_validation(self):
        assert normalize_mac("02-00-00-00-00-53") == "02:00:00:00:00:53"
        with pytest.raises(ValueError):
            normalize_mac("not-a-mac")
        with pytest.raises(ValueError):
            validate_ipv4("10.0.0.999")

    def test_list_servers_shows_reservations(self):
        text = self.tools.list_dhcp_servers("dev")[0].text
        assert "DHCP Server ID 6: interface vlan10" in text and "10.0.0.53  02:00:00:00:00:53" in text

    def test_list_leases_filters_interface(self):
        self.api.get_dhcp_leases.return_value = {"results": [
            {"ip": "10.0.0.57", "mac": "aa:bb:cc:dd:ee:01", "hostname": "laptop-1", "interface": "vlan10", "status": "leased", "expire_time": 1793176615},
            {"ip": "192.168.1.120", "mac": "aa:bb:cc:dd:ee:02", "hostname": "X", "interface": "lan", "status": "leased", "expire_time": 1793176615},
        ]}
        text = self.tools.list_dhcp_leases("dev", interface="lan")[0].text
        assert "192.168.1.120" in text and "10.0.0.57" not in text

    def test_create_reservation_infers_server_from_ip(self):
        text = self.tools.create_dhcp_reservation("dev", "10.0.0.40", "AA:BB:CC:DD:EE:FF", description="HR workstation")[0].text
        assert "on DHCP server 6" in text
        server_id, payload = self.api.create_dhcp_reservation.call_args.args[:2]
        assert server_id == "6"
        assert payload == {"ip": "10.0.0.40", "mac": "aa:bb:cc:dd:ee:ff", "action": "reserved", "description": "HR workstation"}

    def test_create_reservation_rejects_duplicate_ip_and_mac(self):
        assert "already reserved" in self.tools.create_dhcp_reservation("dev", "10.0.0.53", "aa:bb:cc:dd:ee:ff")[0].text
        assert "already has a reservation" in self.tools.create_dhcp_reservation("dev", "10.0.0.70", "02:00:00:00:00:53")[0].text
        self.api.create_dhcp_reservation.assert_not_called()

    def test_create_reservation_by_interface_and_unknown(self):
        self.tools.create_dhcp_reservation("dev", "192.168.1.150", "aa:bb:cc:dd:ee:ff", interface="lan")
        assert self.api.create_dhcp_reservation.call_args.args[0] == "1"
        text = self.tools.create_dhcp_reservation("dev", "172.16.9.9", "aa:bb:cc:dd:ee:fe")[0].text
        assert "Error" in text and "No DHCP server covers" in text

    def test_delete_reservation_by_mac(self):
        text = self.tools.delete_dhcp_reservation("dev", mac="02:00:00:00:00:53")[0].text
        assert "Deleted reservation 3" in text
        self.api.delete_dhcp_reservation.assert_called_once_with("6", "3", vdom=None)

    def test_delete_reservation_requires_identifier_and_match(self):
        assert "Error" in self.tools.delete_dhcp_reservation("dev")[0].text
        assert "No matching" in self.tools.delete_dhcp_reservation("dev", ip="10.0.0.99")[0].text
        self.api.delete_dhcp_reservation.assert_not_called()


# --- security profiles ------------------------------------------------------

class TestSecurityProfileTools:
    def setup_method(self):
        self.manager, self.api = _manager_with_mock()
        self.tools = SecurityProfileTools(self.manager)

    def test_invalid_type_rejected(self):
        text = self.tools.list_security_profiles("dev", "bogus")[0].text
        assert "Error" in text
        self.api.get_security_profiles.assert_not_called()

    def test_list_application_profiles_summary(self):
        self.api.get_security_profiles.return_value = {"results": [{
            "name": "app-x", "comment": "c", "other-application-action": "pass", "unknown-application-action": "pass",
            "entries": [{"action": "block"}, {"action": "pass"}, {"action": "block"}],
        }]}
        text = self.tools.list_security_profiles("dev", "application")[0].text
        assert "Profile: app-x" in text and "Entries: 3 (block: 2, pass: 1)" in text

    def test_detail_resolves_application_names(self):
        self.api.get_security_profile.return_value = {"results": [{
            "name": "app-x", "entries": [
                {"id": 1, "action": "pass", "log": "enable", "category": [], "application": [{"id": 39164}]},
                {"id": 2, "action": "block", "log": "enable", "category": [{"id": 7}], "application": []},
            ],
        }]}
        self.api.get_application_names.return_value = {"results": [{"id": 39164, "name": "AnyDesk", "category": 7}]}
        text = self.tools.get_security_profile_detail("dev", "application", "app-x")[0].text
        assert "AnyDesk [39164]" in text and "7 (Remote.Access)" in text
        self.api.get_application_names.assert_called_once_with([39164], vdom=None)


# --- vpn / users ------------------------------------------------------------

class TestVpnAndUsers:
    def setup_method(self):
        self.manager, self.api = _manager_with_mock()

    def test_ipsec_states(self):
        self.api.get_ipsec_tunnels.return_value = {"results": [
            {"name": "branch-vpn", "rgwy": "1.2.3.4", "incoming_bytes": 2048, "outgoing_bytes": 10,
             "proxyid": [{"p2name": "p2", "status": "up", "expire": 5, "proxy_src": [{"subnet": "10.0.0.0/24"}], "proxy_dst": [{"subnet": "10.0.9.0/24"}]}]},
            {"name": "dialup-vpn", "rgwy": "0.0.0.0", "proxyid": [], "connection_count": 2},
            {"name": "dead", "rgwy": "5.6.7.8", "proxyid": [{"p2name": "x", "status": "down"}]},
        ]}
        text = VpnTools(self.manager).list_ipsec_tunnels("dev")[0].text
        assert "branch-vpn  [UP]" in text and "dialup-vpn  [dialup (2 connected)]" in text and "dead  [DOWN]" in text
        assert "10.0.0.0/24 -> 10.0.9.0/24" in text and "in 2.0 KB" in text

    def test_users_and_groups(self):
        self.api.get_local_users.return_value = {"results": [{"name": "alice", "status": "enable", "type": "password", "two-factor": "email", "email-to": "a@x"}]}
        self.api.get_user_groups.return_value = {"results": [{"name": "G", "group-type": "firewall", "member": [{"name": "alice"}], "match": [{"server-name": "ad", "group-name": "CN=x"}]}]}
        self.api.get_firewall_auth_users.return_value = {"results": [{"username": "alice", "src_ip": "10.0.0.1", "method": "fw"}]}
        tools = UserTools(self.manager)
        assert "2FA=email" in tools.list_local_users("dev")[0].text
        text = tools.list_user_groups("dev")[0].text
        assert "Members: alice" in text and "ad:CN=x" in text
        assert "username=alice" in tools.list_firewall_auth_sessions("dev")[0].text


# --- system -----------------------------------------------------------------

class TestSystemTools:
    def setup_method(self):
        self.manager, self.api = _manager_with_mock()
        self.tools = SystemTools(self.manager)

    def test_resources(self):
        self.api.get_resource_usage.return_value = {"results": {"cpu": [{"current": 5}], "mem": [{"current": 72}], "session": [{"current": 1373}]}}
        text = self.tools.get_system_resources("dev")[0].text
        assert "CPU %: 5" in text and "Sessions (IPv4): 1373" in text

    def test_sessions_filters_and_cap(self):
        self.api.get_sessions.return_value = {"results": {"details": [
            {"proto": "tcp", "saddr": "10.0.0.25", "sport": 1, "srcintf": "lan", "daddr": "10.0.9.18", "dport": 445, "dstintf": "branch-vpn", "policyid": 61, "duration": 3, "sentbyte": 10, "rcvdbyte": 20}
        ]}}
        text = self.tools.list_active_sessions("dev", source_ip="10.0.0.25", destination_port=445, policy_id="61", count=9999)[0].text
        assert "10.0.0.25:1" in text and "policy 61" in text
        kwargs = self.api.get_sessions.call_args.kwargs
        assert kwargs["filters"] == ["srcaddr==10.0.0.25", "dstport==445", "policyid==61"]
        assert kwargs["count"] == 500

    def test_sessions_reject_injection(self):
        text = self.tools.list_active_sessions("dev", source_ip="10.0.0.1&x=1")[0].text
        assert "Error" in text
        self.api.get_sessions.assert_not_called()

    def test_traffic_log_filters(self):
        self.api.get_traffic_logs.return_value = {"results": [
            {"date": "2026-10-26", "time": "14:54:25", "action": "deny", "srcip": "10.0.0.25", "srcport": 5, "srcintf": "lan",
             "dstip": "1.1.1.1", "dstport": 443, "dstintf": "wan", "service": "HTTPS", "policyid": 5, "policyname": "inet", "sentbyte": 1, "rcvdbyte": 2}
        ]}
        text = self.tools.query_traffic_log("dev", source_ip="10.0.0.25", action="deny", raw_filter="dstport==443")[0].text
        assert "deny" in text and "policy 5 (inet)" in text
        kwargs = self.api.get_traffic_logs.call_args.kwargs
        assert kwargs["filters"] == ["srcip==10.0.0.25", "action==deny", "dstport==443"]
        assert kwargs["source"] == "memory"

    def test_traffic_log_rejects_bad_raw_filter(self):
        text = self.tools.query_traffic_log("dev", raw_filter="srcip==1;rm -rf /")[0].text
        assert "Error" in text
        self.api.get_traffic_logs.assert_not_called()

    def test_backup_writes_file_and_refuses_overwrite(self, tmp_path):
        self.api.backup_config.return_value = {"text": "#config-version=X\nconfig system global\nend\n", "status_code": 200}
        target = tmp_path / "fgt.conf"
        text = self.tools.backup_config("dev", str(target))[0].text
        assert "Configuration saved to" in text and target.read_text().startswith("#config-version")
        text = self.tools.backup_config("dev", str(target))[0].text
        assert "Error" in text and "already exists" in text
        assert "saved" in self.tools.backup_config("dev", str(target), overwrite=True)[0].text

    def test_backup_rejects_non_config_body(self, tmp_path):
        self.api.backup_config.return_value = {"text": "<html>login</html>", "status_code": 200}
        text = self.tools.backup_config("dev", str(tmp_path / "x.conf"))[0].text
        assert "Error" in text and not (tmp_path / "x.conf").exists()


# --- API layer (respx) ------------------------------------------------------

class TestExtendedApiEndpoints:
    def setup_method(self):
        self.api = FortiGateAPI("t", FortiGateDeviceConfig(host="198.51.100.10", api_token="tok", vdom="root"))
        self.base = "https://198.51.100.10:443/api/v2"

    def test_move_policy_sends_action_and_reference(self):
        with respx.mock(base_url=self.base, assert_all_mocked=True) as router:
            route = router.put("/cmdb/firewall/policy/60").mock(return_value=httpx.Response(200, json={"status": "success"}))
            self.api.move_firewall_policy("60", "before", "55")
            params = route.calls.last.request.url.params
            assert params["action"] == "move" and params["before"] == "55" and params["vdom"] == "root"
        with pytest.raises(ValueError):
            self.api.move_firewall_policy("60", "sideways", "55")
        with pytest.raises(ValueError):
            self.api.move_firewall_policy("60", "before", "55?x=1")

    def test_dhcp_reservation_child_table_paths(self):
        with respx.mock(base_url=self.base, assert_all_mocked=True) as router:
            post = router.post("/cmdb/system.dhcp/server/6/reserved-address").mock(return_value=httpx.Response(200, json={"status": "success"}))
            delete = router.delete("/cmdb/system.dhcp/server/6/reserved-address/3").mock(return_value=httpx.Response(200, json={"status": "success"}))
            self.api.create_dhcp_reservation("6", {"ip": "10.0.0.40", "mac": "aa:bb:cc:dd:ee:ff"})
            self.api.delete_dhcp_reservation("6", "3")
            assert json.loads(post.calls.last.request.content) == {"ip": "10.0.0.40", "mac": "aa:bb:cc:dd:ee:ff"}
            assert delete.called
        with pytest.raises(ValueError):
            self.api.delete_dhcp_reservation("6", "../1")

    def test_traffic_log_repeats_filter_param(self):
        with respx.mock(base_url=self.base, assert_all_mocked=True) as router:
            route = router.get("/log/memory/traffic/forward").mock(return_value=httpx.Response(200, json={"results": []}))
            self.api.get_traffic_logs(rows=5, filters=["srcip==10.0.0.25", "action==deny"])
            params = route.calls.last.request.url.params
            assert params.get_list("filter") == ["srcip==10.0.0.25", "action==deny"] and params["rows"] == "5"
        with pytest.raises(ValueError):
            self.api.get_traffic_logs(source="tape")

    def test_sessions_use_filter_expressions(self):
        with respx.mock(base_url=self.base, assert_all_mocked=True) as router:
            route = router.get("/monitor/firewall/sessions").mock(return_value=httpx.Response(200, json={"results": {"details": []}}))
            self.api.get_sessions(filters=["srcaddr==10.0.0.40"], count=7)
            params = route.calls.last.request.url.params
            assert params.get_list("filter") == ["srcaddr==10.0.0.40"] and params["count"] == "7"
            assert "srcaddr" not in params

    def test_backup_returns_raw_text(self):
        with respx.mock(base_url=self.base, assert_all_mocked=True) as router:
            router.post("/monitor/system/config/backup").mock(return_value=httpx.Response(200, text="#config-version=FGT\nconfig system global\nend\n"))
            result = self.api.backup_config()
            assert result["status_code"] == 200 and result["text"].startswith("#config-version")

    def test_security_profile_endpoints(self):
        assert self.api._security_profile_endpoint("application") == "cmdb/application/list"
        with pytest.raises(ValueError):
            self.api._security_profile_endpoint("firewall")
        with respx.mock(base_url=self.base, assert_all_mocked=True) as router:
            route = router.get("/cmdb/application/name").mock(return_value=httpx.Response(200, json={"results": []}))
            self.api.get_application_names([39164, 15832, 39164])
            assert route.calls.last.request.url.params["filter"] == "id==15832,id==39164"
            assert self.api.get_application_names([]) == {"results": []}

    @pytest.mark.parametrize("method, verb, path", [
        ("get_address_groups", "GET", "/cmdb/firewall/addrgrp"),
        ("get_service_groups", "GET", "/cmdb/firewall.service/group"),
        ("get_dhcp_servers", "GET", "/cmdb/system.dhcp/server"),
        ("get_dhcp_leases", "GET", "/monitor/system/dhcp"),
        ("get_ipsec_tunnels", "GET", "/monitor/vpn/ipsec"),
        ("get_ssl_vpn_sessions", "GET", "/monitor/vpn/ssl"),
        ("get_local_users", "GET", "/cmdb/user/local"),
        ("get_user_groups", "GET", "/cmdb/user/group"),
        ("get_firewall_auth_users", "GET", "/monitor/user/firewall"),
        ("get_resource_usage", "GET", "/monitor/system/resource/usage"),
        ("get_sessions", "GET", "/monitor/firewall/sessions"),
    ])
    def test_read_endpoints(self, method, verb, path):
        with respx.mock(base_url=self.base, assert_all_mocked=True) as router:
            route = router.request(verb, path).mock(return_value=httpx.Response(200, json={"results": []}))
            getattr(self.api, method)()
            assert route.called


# --- templates ----------------------------------------------------------------

def test_template_helpers_render_values():
    assert FortiGateTemplates._render_address_value({"type": "interface-subnet", "interface": "lan"}) == "interface-subnet lan"
    assert FortiGateTemplates._render_address_value(None) == "Not resolved"
    assert FortiGateTemplates._render_service_value({"protocol": "TCP/UDP", "tcp-portrange": "80", "udp-portrange": "53"}) == "TCP 80, UDP 53"
    assert FortiGateTemplates._fmt_bytes(1536) == "1.5 KB"
    assert "No DHCP servers" in FortiGateTemplates.dhcp_servers({"results": []})
    assert "No matching log records" in FortiGateTemplates.traffic_log({})
