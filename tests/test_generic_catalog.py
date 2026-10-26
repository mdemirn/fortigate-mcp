"""Tests for the generic pass-through tools, the declarative catalog and the
parameterized diagnostics (policy/route lookup, FortiView, logs, tunnel actions)."""
import json
from unittest.mock import MagicMock

import httpx
import pytest
import respx

from src.fortigate_mcp.config.models import AuthConfig, FortiGateDeviceConfig
from src.fortigate_mcp.core.fortigate import FortiGateAPI, FortiGateManager
from src.fortigate_mcp.tools.catalog import CATALOG, CATALOG_BY_NAME, CatalogTools
from src.fortigate_mcp.tools.firewall import FirewallTools
from src.fortigate_mcp.tools.generic import MAX_OUTPUT_CHARS, GenericTools
from src.fortigate_mcp.tools.routing import RoutingTools
from src.fortigate_mcp.tools.security import PROFILE_TYPES
from src.fortigate_mcp.tools.system import SystemTools
from src.fortigate_mcp.tools.vpn import VpnTools
from src.fortigate_mcp.validation import redact_sensitive_fields, validate_api_key, validate_api_path


def _manager_with_mock():
    manager = FortiGateManager({}, AuthConfig(require_auth=False, api_tokens=[], allowed_origins=["*"]))
    api = MagicMock(spec=FortiGateAPI)
    api.device_id = "dev"
    manager.devices["dev"] = api
    return manager, api


# --- validation ---------------------------------------------------------------

@pytest.mark.parametrize("path", ["firewall/policy", "vpn.ipsec/phase1-interface", "system.dhcp/server", "log.syslogd/setting", "system/status"])
def test_api_path_accepts_fortios_paths(path):
    assert validate_api_path(path) == path


@pytest.mark.parametrize("path", ["../etc", "firewall/policy?x=1", "/firewall/policy", "firewall/policy/", "a b", "", "x#y", "a/b/c/d/e/f/g"])
def test_api_path_rejects_injection(path):
    with pytest.raises(ValueError):
        validate_api_path(path)


def test_api_key_grammar():
    assert validate_api_key("G Suite") == "G Suite"
    assert validate_api_key("port1.100") == "port1.100"
    for bad in ("../1", "a?b", "x\r\ny", "a/b"):
        with pytest.raises(ValueError):
            validate_api_key(bad)


def test_redaction_masks_secret_keys_only():
    data = {"name": "t", "psksecret": "ENC x", "password": "", "snmp": [{"community": "public"}], "wpa-passphrase": "x", "comment": "keep"}
    out = redact_sensitive_fields(data)
    assert out["psksecret"] == "***REDACTED***" and out["snmp"][0]["community"] == "***REDACTED***"
    assert out["password"] == "" and out["comment"] == "keep" and out["name"] == "t"


# --- API layer ----------------------------------------------------------------

class TestGenericApi:
    def setup_method(self):
        self.api = FortiGateAPI("t", FortiGateDeviceConfig(host="198.51.100.10", api_token="tok", vdom="root"))
        self.base = "https://198.51.100.10:443/api/v2"

    def test_cmdb_key_is_percent_encoded(self):
        with respx.mock(base_url=self.base, assert_all_mocked=True) as router:
            route = router.get("/cmdb/firewall/addrgrp/G%20Suite").mock(return_value=httpx.Response(200, json={"results": []}))
            self.api.cmdb_get("firewall/addrgrp", "G Suite")
            assert route.called

    def test_cmdb_list_params_and_update_delete(self):
        with respx.mock(base_url=self.base, assert_all_mocked=True) as router:
            lst = router.get("/cmdb/firewall/policy").mock(return_value=httpx.Response(200, json={"results": []}))
            upd = router.put("/cmdb/system/interface/port1.100").mock(return_value=httpx.Response(200, json={"status": "success"}))
            dele = router.delete("/cmdb/firewall/ippool/p1").mock(return_value=httpx.Response(200, json={"status": "success"}))
            self.api.cmdb_list("firewall/policy", params={"filter": ["status==enable"], "format": "policyid|name"})
            self.api.cmdb_update("system/interface", "port1.100", {"description": "x"})
            self.api.cmdb_delete("firewall/ippool", "p1")
            params = lst.calls.last.request.url.params
            assert params["filter"] == "status==enable" and params["format"] == "policyid|name"
            assert json.loads(upd.calls.last.request.content) == {"description": "x"} and dele.called

    def test_monitor_post_sends_body_and_log_get_filters(self):
        with respx.mock(base_url=self.base, assert_all_mocked=True) as router:
            post = router.post("/monitor/vpn/ipsec/tunnel_down").mock(return_value=httpx.Response(200, json={"status": "success"}))
            log = router.get("/log/memory/event/vpn").mock(return_value=httpx.Response(200, json={"results": []}))
            self.api.monitor_post("vpn/ipsec/tunnel_down", data={"p1name": "branch-vpn"})
            self.api.log_get("memory/event/vpn", rows=3, filters=["user==x"])
            assert json.loads(post.calls.last.request.content) == {"p1name": "branch-vpn"}
            assert log.calls.last.request.url.params["rows"] == "3"

    def test_generic_rejects_bad_path_before_request(self):
        with pytest.raises(ValueError):
            self.api.cmdb_list("../x")
        with pytest.raises(ValueError):
            self.api.monitor_get("system/status?x=1")


# --- generic tools ----------------------------------------------------------------

class TestGenericTools:
    def setup_method(self):
        self.manager, self.api = _manager_with_mock()
        self.tools = GenericTools(self.manager)

    def test_cmdb_list_redacts_and_formats(self):
        self.api.cmdb_list.return_value = {"results": [{"name": "branch-vpn", "psksecret": "ENC abc"}]}
        text = self.tools.cmdb_list("dev", "vpn.ipsec/phase1-interface", filter_expr="name==branch-vpn&type==static", count=5)[0].text
        assert "cmdb/vpn.ipsec/phase1-interface" in text and "***REDACTED***" in text and "ENC abc" not in text
        params = self.api.cmdb_list.call_args.kwargs["params"]
        assert params == {"filter": ["name==branch-vpn", "type==static"], "count": 5}

    def test_output_truncation(self):
        self.api.monitor_get.return_value = {"results": [{"i": i, "pad": "x" * 100} for i in range(2000)]}
        text = self.tools.monitor_get("dev", "router/ipv4")[0].text
        assert len(text) < MAX_OUTPUT_CHARS + 500 and "truncated" in text

    def test_create_reports_mkey_and_delete(self):
        self.api.cmdb_create.return_value = {"status": "success", "mkey": "pool-1"}
        assert "(key pool-1)" in self.tools.create_cmdb_object("dev", "firewall/ippool", {"name": "pool-1"})[0].text
        assert "Deleted cmdb/firewall/ippool/pool-1" in self.tools.delete_cmdb_object("dev", "firewall/ippool", "pool-1")[0].text
        assert "Updated" in self.tools.update_cmdb_object("dev", "firewall/ippool", "pool-1", {"comments": "c"})[0].text

    def test_bad_path_is_error_not_exception(self):
        self.api.cmdb_list.side_effect = ValueError("path is not a valid FortiOS API path")
        text = self.tools.cmdb_list("dev", "../x")[0].text
        assert "Error" in text

    def test_log_get_and_monitor_action(self):
        self.api.log_get.return_value = {"results": [{"logdesc": "Admin login"}]}
        text = self.tools.log_get("dev", "memory/event/system", rows=9999, filter_expr="user==admin")[0].text
        assert "Admin login" in text
        assert self.api.log_get.call_args.kwargs["rows"] == 500
        self.api.monitor_post.return_value = {"status": "success"}
        assert "(POST)" in self.tools.execute_monitor_action("dev", "vpn/ipsec/tunnel_up", {"p1name": "x"})[0].text


# --- catalog ------------------------------------------------------------------------

def test_catalog_entries_are_unique_and_well_formed():
    names = [e.name for e in CATALOG]
    assert len(names) == len(set(names))
    for entry in CATALOG:
        assert entry.section in ("cmdb", "monitor")
        validate_api_path(entry.path)
        assert entry.name.startswith(("list_", "get_"))
        assert len(entry.description) > 20


class TestCatalogTools:
    def setup_method(self):
        self.manager, self.api = _manager_with_mock()
        self.tools = CatalogTools(self.manager)

    def test_cmdb_entry_renders_preferred_keys_and_redacts(self):
        self.api.cmdb_list.return_value = {"results": [{"name": "branch-vpn", "type": "static", "remote-gw": "1.2.3.4", "psksecret": "ENC x", "ike-version": "2"}]}
        text = self.tools.run("list_ipsec_phase1", "dev")[0].text
        assert "IPsec Phase 1 Interfaces (1)" in text and "remote-gw=1.2.3.4" in text and "ENC x" not in text
        self.api.cmdb_list.assert_called_once_with("vpn.ipsec/phase1-interface", params=None, vdom=None)

    def test_monitor_entry_passes_params(self):
        self.api.monitor_get.return_value = {"results": []}
        text = self.tools.run("list_endpoint_devices", "dev", vdom="root")[0].text
        assert "Detected Devices (0)" in text
        self.api.monitor_get.assert_called_once_with("user/device/query", params={"number": 500}, vdom="root")

    def test_unknown_name_raises(self):
        with pytest.raises(ValueError):
            self.tools.run("nope", "dev")

    def test_api_error_becomes_error_content(self):
        self.api.monitor_get.side_effect = RuntimeError("boom")
        text = self.tools.run("list_arp_table", "dev")[0].text
        assert "Error" in text and "list arp table" in text

    def test_every_entry_runs(self):
        self.api.cmdb_list.return_value = {"results": [{"name": "x"}]}
        self.api.monitor_get.return_value = {"results": [{"name": "x"}]}
        for entry in CATALOG:
            text = self.tools.run(entry.name, "dev")[0].text
            assert entry.title in text, entry.name
        assert CATALOG_BY_NAME["list_arp_table"].section == "monitor"


# --- diagnostics ----------------------------------------------------------------------

class TestDiagnostics:
    def setup_method(self):
        self.manager, self.api = _manager_with_mock()

    def test_lookup_policy_maps_protocol_and_formats(self):
        self.api.monitor_get.return_value = {"results": {"policy_id": 61, "policy_name": "hr-pc-to-fileserver", "action": "accept"}}
        text = FirewallTools(self.manager).lookup_policy("dev", "10.0.0.25", "10.0.9.18", 445, source_interface="vlan10")[0].text
        assert "policy_name: hr-pc-to-fileserver" in text and "TCP 10.0.0.25 -> 10.0.9.18:445 via vlan10" in text
        params = self.api.monitor_get.call_args.kwargs["params"]
        assert params["protocol"] == 6 and params["srcintf"] == "vlan10" and params["destport"] == 445

    def test_lookup_policy_rejects_bad_input(self):
        tools = FirewallTools(self.manager)
        assert "Error" in tools.lookup_policy("dev", "not-an-ip", "10.0.9.18", 445)[0].text
        assert "Error" in tools.lookup_policy("dev", "10.0.0.1", "10.0.9.18", 445, protocol="gre!")[0].text
        self.api.monitor_get.assert_not_called()

    def test_lookup_route(self):
        self.api.monitor_get.return_value = {"results": {"interface": "branch-vpn", "gateway": "0.0.0.0", "type": "static"}}
        text = RoutingTools(self.manager).lookup_route("dev", "10.0.9.18")[0].text
        assert "interface: branch-vpn" in text
        assert "Error" in RoutingTools(self.manager).lookup_route("dev", "nope")[0].text

    def test_ipsec_tunnel_action(self):
        tools = VpnTools(self.manager)
        assert "brought down" in tools.execute_ipsec_tunnel_action("dev", "branch-vpn", "down", "branch-vpn-p2")[0].text
        self.api.monitor_post.assert_called_once_with("vpn/ipsec/tunnel_down", data={"p1name": "branch-vpn", "p2name": "branch-vpn-p2"}, vdom=None)
        assert "Error" in tools.execute_ipsec_tunnel_action("dev", "branch-vpn", "sideways")[0].text
        assert "Error" in tools.execute_ipsec_tunnel_action("dev", "bad name", "up")[0].text

    def test_fortiview_top(self):
        self.api.monitor_get.return_value = {"results": {"details": [{"srcip": "10.0.0.40", "srcname": "PC", "sessions": 12, "bytes": 2048, "bandwidth": 5}]}}
        text = SystemTools(self.manager).get_fortiview_top("dev", report_by="source", count=5)[0].text
        assert "10.0.0.40" in text and "(PC)" in text and "2.0 KB" in text
        assert self.api.monitor_get.call_args.kwargs["params"]["report_by"] == "source"
        assert "Error" in SystemTools(self.manager).get_fortiview_top("dev", report_by="nope")[0].text

    def test_event_and_utm_logs(self):
        tools = SystemTools(self.manager)
        self.api.log_get.return_value = {"results": [{"date": "2026-10-26", "time": "10:00:00", "level": "notice", "logdesc": "Admin login successful", "user": "admin", "msg": "ok"}]}
        text = tools.query_event_log("dev", category="system", raw_filter="user==admin")[0].text
        assert "Admin login successful" in text and "user=admin" in text
        assert self.api.log_get.call_args.args[0] == "memory/event/system"
        self.api.log_get.return_value = {"results": [{"date": "d", "time": "t", "action": "blocked", "srcip": "10.0.0.5", "dstip": "1.1.1.1", "dstport": 443, "hostname": "bad.example", "catdesc": "Malicious", "policyid": 5}]}
        text = tools.query_utm_log("dev", log_type="webfilter", source_ip="10.0.0.5")[0].text
        assert "bad.example" in text and "[Malicious]" in text and "policy 5" in text
        assert self.api.log_get.call_args.kwargs["filters"] == ["srcip==10.0.0.5"]
        assert "Error" in tools.query_event_log("dev", category="nope")[0].text
        assert "Error" in tools.query_utm_log("dev", log_type="nope")[0].text

    def test_log_settings_tolerates_missing_tables(self):
        def fake(path, vdom=None):
            if path == "log.disk/setting":
                raise RuntimeError("no disk")
            return {"results": {"status": "enable", "server": "10.0.9.100", "port": 6514}}
        self.api.cmdb_list.side_effect = fake
        text = SystemTools(self.manager).get_log_settings("dev")[0].text
        assert "Syslog: status=enable, server=10.0.9.100, port=6514" in text and "Disk: unavailable" in text

    def test_ping_and_geoip(self):
        tools = SystemTools(self.manager)
        self.api.monitor_get.return_value = {"results": {"packets_sent": 5, "packets_received": 5, "avg_rtt": 1.2}}
        assert "packets_received: 5" in tools.ping_from_device("dev", "10.0.9.18")[0].text
        assert "Error" in tools.ping_from_device("dev", "10.0.9.18;x")[0].text
        self.api.monitor_post.return_value = {"results": [{"ip": "8.8.8.8", "country_name": "United States"}]}
        assert "country_name=United States" in tools.geoip_lookup("dev", "8.8.8.8")[0].text


def test_security_profile_types_extended():
    assert "dlp" in PROFILE_TYPES and "waf" in PROFILE_TYPES
