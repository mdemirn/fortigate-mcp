"""
Template system for FortiGate MCP response formatting.

This module provides structured templates for formatting FortiGate API responses
into human-readable and consistent output formats. Templates are organized by
resource type and operation.
"""
from typing import Dict, Any, Optional
from datetime import datetime

class FortiGateTemplates:
    """Template collection for FortiGate resource formatting.
    
    Provides static methods for formatting different types of FortiGate
    resources into structured, readable text output.
    """
    
    @staticmethod
    def device_list(devices: Dict[str, Dict[str, Any]]) -> str:
        """Format device list for display.
        
        Args:
            devices: Dictionary of device info keyed by device ID
            
        Returns:
            Formatted string with device information
        """
        if not devices:
            return "No FortiGate devices configured"
        
        lines = ["FortiGate Devices", ""]
        
        for device_id, info in devices.items():
            lines.extend([
                f"Device: {device_id}",
                f"  Host: {info['host']}:{info['port']}",
                f"  VDOM: {info['vdom']}",
                f"  Auth: {info['auth_method']}",
                f"  SSL Verify: {'Yes' if info['verify_ssl'] else 'No'}",
                ""
            ])
        
        return "\n".join(lines)
    
    @staticmethod
    def device_status(device_id: str, status_data: Dict[str, Any]) -> str:
        """Format device system status.
        
        Args:
            device_id: Device identifier
            status_data: System status response from FortiGate API
            
        Returns:
            Formatted system status information
        """
        lines = [f"Device Status: {device_id}", ""]
        
        if "results" in status_data:
            results = status_data["results"]
            
            lines.extend([
                "System Information",
                f"  Model: {results.get('model_name', 'Unknown')} {results.get('model_number', '')}",
                f"  Hostname: {results.get('hostname', 'Unknown')}",
                f"  Version: {status_data.get('version', 'Unknown')}",
                f"  Serial: {status_data.get('serial', 'Unknown')}",
                f"  VDOM: {status_data.get('vdom', 'Unknown')}",
                ""
            ])
            
            # Add additional status info if available
            if results.get('log_disk_status'):
                lines.append(f"  Log Disk: {results['log_disk_status']}")
            if results.get('current_time'):
                lines.append(f"  Current Time: {results['current_time']}")
        else:
            lines.append("No status information available")
        
        return "\n".join(lines)
    
    @staticmethod
    def firewall_policies(policies_data: Dict[str, Any]) -> str:
        """Format firewall policies list.
        
        Args:
            policies_data: Firewall policies response from FortiGate API
            
        Returns:
            Formatted firewall policies information
        """
        lines = ["Firewall Policies", ""]
        
        if "results" in policies_data and policies_data["results"]:
            policies = policies_data["results"]
            
            for policy in policies:
                status = "Enabled" if policy.get("status") == "enable" else "Disabled"
                action = policy.get("action", "unknown")
                
                # Extract source addresses from dict list
                srcaddr_list = policy.get('srcaddr', [])
                src_names = []
                for addr in srcaddr_list:
                    if isinstance(addr, dict) and 'name' in addr:
                        src_names.append(addr['name'])
                    elif isinstance(addr, str):
                        src_names.append(addr)
                src_text = ', '.join(src_names)
                
                # Extract destination addresses from dict list
                dstaddr_list = policy.get('dstaddr', [])
                dst_names = []
                for addr in dstaddr_list:
                    if isinstance(addr, dict) and 'name' in addr:
                        dst_names.append(addr['name'])
                    elif isinstance(addr, str):
                        dst_names.append(addr)
                dst_text = ', '.join(dst_names)
                
                # Extract services from dict list
                service_list = policy.get('service', [])
                svc_names = []
                for svc in service_list:
                    if isinstance(svc, dict) and 'name' in svc:
                        svc_names.append(svc['name'])
                    elif isinstance(svc, str):
                        svc_names.append(svc)
                svc_text = ', '.join(svc_names)
                
                lines.extend([
                    f"Policy {policy.get('policyid', 'N/A')} ({status})",
                    f"  Name: {policy.get('name', 'Unnamed')}",
                    f"  Source: {src_text if src_text else 'any'}",
                    f"  Destination: {dst_text if dst_text else 'any'}",
                    f"  Service: {svc_text if svc_text else 'any'}",
                    f"  Action: {action}",
                    ""
                ])
            

                
        else:
            lines.append("No firewall policies found")
        
        return "\n".join(lines)
    
    @staticmethod
    def firewall_policy_detail(policy_data: Dict[str, Any], device_id: str, 
                              address_objects: Optional[Dict[str, Any]] = None,
                              service_objects: Optional[Dict[str, Any]] = None,
                              address_groups: Optional[Dict[str, Any]] = None,
                              service_groups: Optional[Dict[str, Any]] = None) -> str:
        """Format detailed firewall policy information.
        
        Args:
            policy_data: Detailed policy response from FortiGate API
            device_id: Device identifier
            address_objects: Address objects data for resolution
            service_objects: Service objects data for resolution
            address_groups: Address groups data -- lets group members be expanded
            service_groups: Service groups data -- lets group members be expanded
            
        Returns:
            Formatted detailed policy information
        """
        grp_dict = FortiGateTemplates._results_by_name(address_groups)
        svcgrp_dict = FortiGateTemplates._results_by_name(service_groups)
        addr_dict = FortiGateTemplates._results_by_name(address_objects)
        svc_dict = FortiGateTemplates._results_by_name(service_objects)

        def render_addr(name: str, indent: str = "    ") -> list:
            if name in grp_dict:
                members = FortiGateTemplates._names(grp_dict[name].get("member", []))
                out = [f"{indent}{name}: address group ({len(members)} members)"]
                for member in members:
                    if member in grp_dict:
                        out.append(f"{indent}  {member}: nested address group")
                    else:
                        out.append(f"{indent}  {member}: {FortiGateTemplates._render_address_value(addr_dict.get(member))}")
                return out
            return [f"{indent}{name}: {FortiGateTemplates._render_address_value(addr_dict.get(name))}"]

        def render_svc(name: str, indent: str = "    ") -> list:
            if name in svcgrp_dict:
                members = FortiGateTemplates._names(svcgrp_dict[name].get("member", []))
                out = [f"{indent}{name}: service group ({len(members)} members)"]
                for member in members:
                    out.append(f"{indent}  {member}: {FortiGateTemplates._render_service_value(svc_dict.get(member))}")
                return out
            return [f"{indent}{name}: {FortiGateTemplates._render_service_value(svc_dict.get(name))}"]
        if "results" not in policy_data or not policy_data["results"]:
            return f"Policy not found on device {device_id}"
        
        # FortiGate API returns results as a single object for specific policy ID
        results = policy_data["results"]
        if isinstance(results, list):
            if not results:
                return f"Policy not found on device {device_id}"
            policy = results[0]  # Get first (and only) policy from list
        else:
            policy = results
        lines = [f"Policy Detail - Device: {device_id}", ""]
        
        # Basic Policy Information
        lines.extend([
            "Basic Information",
            f"  Policy ID: {policy.get('policyid', 'N/A')}",
            f"  Policy Name: {policy.get('name', 'Unnamed')}",
            f"  Status: {'Active' if policy.get('status') == 'enable' else 'Disabled'}",
            f"  UUID: {policy.get('uuid', 'N/A')}",
            ""
        ])
        
        # Traffic Direction
        src_intf = policy.get('srcintf', [])
        dst_intf = policy.get('dstintf', [])
        src_intf_names = [intf.get('name', 'unknown') if isinstance(intf, dict) else str(intf) for intf in src_intf]
        dst_intf_names = [intf.get('name', 'unknown') if isinstance(intf, dict) else str(intf) for intf in dst_intf]
        
        lines.extend([
            "Traffic Direction",
            f"  Source Interface: {', '.join(src_intf_names)}",
            f"  Destination Interface: {', '.join(dst_intf_names)}",
            ""
        ])
        
        # Source Information
        srcaddr_list = policy.get('srcaddr', [])
        src_names = []
        for addr in srcaddr_list:
            if isinstance(addr, dict) and 'name' in addr:
                src_names.append(addr['name'])
            elif isinstance(addr, str):
                src_names.append(addr)
        
        lines.extend([
            "Source",
            f"  Address Objects: {', '.join(src_names)}",
            f"  Total Objects: {len(src_names)}",
        ])
        
        # Resolve source addresses if address_objects provided
        if address_objects and "results" in address_objects:
            lines.append("  Resolved Addresses:")
            for src_name in src_names:
                lines.extend(render_addr(src_name))
        
        lines.append("")
        
        # Destination Information
        dstaddr_list = policy.get('dstaddr', [])
        dst_names = []
        for addr in dstaddr_list:
            if isinstance(addr, dict) and 'name' in addr:
                dst_names.append(addr['name'])
            elif isinstance(addr, str):
                dst_names.append(addr)
        
        lines.extend([
            "Destination",
            f"  Address Objects: {', '.join(dst_names)}",
            f"  Total Objects: {len(dst_names)}",
        ])
        
        # Resolve destination addresses
        if address_objects and "results" in address_objects:
            lines.append("  Resolved Addresses:")
            for dst_name in dst_names:
                lines.extend(render_addr(dst_name))
        
        lines.append("")
        
        # Service Information
        service_list = policy.get('service', [])
        svc_names = []
        for svc in service_list:
            if isinstance(svc, dict) and 'name' in svc:
                svc_names.append(svc['name'])
            elif isinstance(svc, str):
                svc_names.append(svc)
        
        lines.extend([
            "Services",
            f"  Service Objects: {', '.join(svc_names)}",
            f"  Total Services: {len(svc_names)}",
        ])
        
        # Resolve services
        if service_objects and "results" in service_objects:
            lines.append("  Resolved Services:")
            for svc_name in svc_names:
                lines.extend(render_svc(svc_name))
        
        lines.append("")
        
        # Action and Security
        action = policy.get('action', 'unknown')
        
        lines.extend([
            "Action and Security",
            f"  Action: {action.upper()}",
            f"  Log Traffic: {'Yes' if policy.get('logtraffic') == 'all' else 'No'}",
            f"  NAT: {'Yes' if policy.get('nat') == 'enable' else 'No'}",
        ])
        
        # Schedule -- cmdb policy responses carry this as a plain string
        # (e.g. "always"); indexing a string would render its first char.
        schedule = policy.get('schedule', 'always')
        if isinstance(schedule, str):
            schedule_name = schedule or 'always'
        elif schedule and isinstance(schedule[0], dict):
            schedule_name = schedule[0].get('name', 'always')
        else:
            schedule_name = str(schedule[0]) if schedule else 'always'
        lines.append(f"  Schedule: {schedule_name}")
        if policy.get('nat') == 'enable' and policy.get('ippool') == 'enable':
            lines.append(f"  NAT IP Pool: {', '.join(FortiGateTemplates._names(policy.get('poolname', []))) or 'N/A'}")

        # Identity-based restrictions (users/groups) -- when present, an
        # unauthenticated flow that otherwise matches this policy does NOT
        # match it and falls through to the next policy.
        users = FortiGateTemplates._names(policy.get('users', []))
        groups = FortiGateTemplates._names(policy.get('groups', []))
        fsso_groups = FortiGateTemplates._names(policy.get('fsso-groups', []))
        if users or groups or fsso_groups:
            lines.extend(["", "Identity (authentication required)"])
            if users:
                lines.append(f"  Users: {', '.join(users)}")
            if groups:
                lines.append(f"  Groups: {', '.join(groups)}")
            if fsso_groups:
                lines.append(f"  FSSO Groups: {', '.join(fsso_groups)}")

        # Security profile names
        profile_fields = [
            ("Application Control", "application-list"),
            ("Web Filter", "webfilter-profile"),
            ("Antivirus", "av-profile"),
            ("IPS", "ips-sensor"),
            ("DNS Filter", "dnsfilter-profile"),
            ("SSL/SSH Inspection", "ssl-ssh-profile"),
            ("Protocol Options", "profile-protocol-options"),
        ]
        active_profiles = [(label, policy.get(key)) for label, key in profile_fields if policy.get(key)]
        lines.extend(["", "Security Profiles"])
        lines.append(f"  UTM Status: {policy.get('utm-status', 'N/A')}")
        if policy.get('inspection-mode'):
            lines.append(f"  Inspection Mode: {policy['inspection-mode']}")
        if active_profiles:
            for label, value in active_profiles:
                lines.append(f"  {label}: {value}")
        else:
            lines.append("  (none)")
        
        # Comments
        if policy.get('comments'):
            lines.extend([
                "",
                "Comments",
                f"  {policy['comments']}"
            ])
        
        lines.append("")
        
        # Technical Details
        lines.extend([
            "Technical Details",
            f"  Sequence Number: {policy.get('seq-num', 'N/A')}",
            f"  Internet Service: {'Yes' if policy.get('internet-service') == 'enable' else 'No'}",
            f"  Application Control: {'Yes' if policy.get('application-list') else 'No'}",
            f"  Antivirus: {'Yes' if policy.get('av-profile') else 'No'}",
            f"  Web Filter: {'Yes' if policy.get('webfilter-profile') else 'No'}",
            f"  IPS: {'Yes' if policy.get('ips-sensor') else 'No'}",
            ""
        ])
        
        return "\n".join(lines)
    
    @staticmethod
    def address_objects(addresses_data: Dict[str, Any]) -> str:
        """Format address objects list.
        
        Args:
            addresses_data: Address objects response from FortiGate API
            
        Returns:
            Formatted address objects information
        """
        lines = ["Address Objects", ""]
        
        if "results" in addresses_data and addresses_data["results"]:
            addresses = addresses_data["results"]
            
            for addr in addresses:
                lines.extend([
                    f"Address Object: {addr.get('name', 'Unnamed')}",
                    f"  Type: {addr.get('type', 'unknown')}",
                ])
                
                # Add type-specific information
                if addr.get("subnet"):
                    lines.append(f"  Subnet: {addr['subnet']}")
                elif addr.get("start-ip") and addr.get("end-ip"):
                    lines.append(f"  Range: {addr['start-ip']} - {addr['end-ip']}")
                elif addr.get("fqdn"):
                    lines.append(f"  FQDN: {addr['fqdn']}")
                
                if addr.get("comment"):
                    lines.append(f"  Comment: {addr['comment']}")
                
                lines.append("")
            

                
        else:
            lines.append("No address objects found")
        
        return "\n".join(lines)
    
    @staticmethod
    def _render_mappedip(mappedip: Any) -> str:
        """Render FortiOS's `mappedip` field as a human-readable string.

        FortiOS's cmdb/firewall/vip GET returns `mappedip` as a table type --
        a list of member objects like [{"range": "192.168.1.100"}] -- even
        when the VIP was created with a plain-string mappedip. Config echoes
        may still carry the plain string, so both shapes are handled.

        Args:
            mappedip: Raw `mappedip` value from the FortiGate API

        Returns:
            Comma-joined range string(s), or "N/A" when absent/empty
        """
        if isinstance(mappedip, list):
            rendered = ", ".join(
                m.get("range", str(m)) if isinstance(m, dict) else str(m)
                for m in mappedip
            )
            return rendered or "N/A"
        if mappedip is None or mappedip == "":
            return "N/A"
        return str(mappedip)

    @staticmethod
    def virtual_ips(vips_data: Dict[str, Any]) -> str:
        """Format virtual IPs list.

        Args:
            vips_data: Virtual IPs response from FortiGate API

        Returns:
            Formatted virtual IPs information
        """
        lines = ["Virtual IPs", ""]

        if "results" in vips_data and vips_data["results"]:
            vips = vips_data["results"]

            for vip in vips:
                mapped = FortiGateTemplates._render_mappedip(vip.get("mappedip"))
                lines.extend([
                    f"Virtual IP: {vip.get('name', 'Unnamed')}",
                    f"  External IP: {vip.get('extip', 'N/A')}",
                    f"  Mapped IP: {mapped}",
                    f"  External Interface: {vip.get('extintf', 'N/A')}",
                    f"  Port Forwarding: {vip.get('portforward', 'disable')}",
                ])
                
                if vip.get("protocol"):
                    lines.append(f"  Protocol: {vip['protocol']}")
                
                if vip.get("extport"):
                    lines.append(f"  External Port: {vip['extport']}")
                
                if vip.get("mappedport"):
                    lines.append(f"  Mapped Port: {vip['mappedport']}")
                
                if vip.get("comment"):
                    lines.append(f"  Comment: {vip['comment']}")
                
                lines.append("")
        else:
            lines.append("No virtual IPs found")
        
        return "\n".join(lines)
    
    @staticmethod
    def virtual_ip_detail(vip_data: Dict[str, Any]) -> str:
        """Format virtual IP detail.
        
        Args:
            vip_data: Virtual IP detail response from FortiGate API
            
        Returns:
            Formatted virtual IP detail information
        """
        lines = ["Virtual IP Detail", ""]
        
        if "results" in vip_data and vip_data["results"]:
            vip = vip_data["results"][0] if isinstance(vip_data["results"], list) else vip_data["results"]

            mapped = FortiGateTemplates._render_mappedip(vip.get("mappedip"))
            lines.extend([
                f"Name: {vip.get('name', 'N/A')}",
                f"External IP: {vip.get('extip', 'N/A')}",
                f"Mapped IP: {mapped}",
                f"External Interface: {vip.get('extintf', 'N/A')}",
                f"Port Forwarding: {vip.get('portforward', 'disable')}",
            ])
            
            if vip.get("protocol"):
                lines.append(f"Protocol: {vip['protocol']}")
            
            if vip.get("extport"):
                lines.append(f"External Port: {vip['extport']}")
            
            if vip.get("mappedport"):
                lines.append(f"Mapped Port: {vip['mappedport']}")
            
            if vip.get("comment"):
                lines.append(f"Comment: {vip['comment']}")
            
            if vip.get("status"):
                lines.append(f"Status: {vip['status']}")
        else:
            lines.append("Virtual IP not found")
        
        return "\n".join(lines)
    
    @staticmethod
    def service_objects(services_data: Dict[str, Any]) -> str:
        """Format service objects list.
        
        Args:
            services_data: Service objects response from FortiGate API
            
        Returns:
            Formatted service objects information
        """
        lines = ["Service Objects", ""]
        
        if "results" in services_data and services_data["results"]:
            services = services_data["results"]
            
            for service in services:
                protocol = service.get("protocol", "unknown").upper()
                
                lines.extend([
                    f"Service: {service.get('name', 'Unnamed')} ({protocol})",
                ])
                
                # Add protocol-specific port information
                if service.get("tcp-portrange"):
                    lines.append(f"  TCP Ports: {service['tcp-portrange']}")
                if service.get("udp-portrange"):
                    lines.append(f"  UDP Ports: {service['udp-portrange']}")
                
                if service.get("comment"):
                    lines.append(f"  Comment: {service['comment']}")
                
                lines.append("")
            

                
        else:
            lines.append("No service objects found")
        
        return "\n".join(lines)
    
    @staticmethod
    def routing_table(routing_data: Dict[str, Any]) -> str:
        """Format routing table.
        
        Args:
            routing_data: Routing table response from FortiGate API
            
        Returns:
            Formatted routing table information
        """
        lines = ["Routing Table", ""]
        
        if "results" in routing_data and routing_data["results"]:
            routes = routing_data["results"]
            
            for route in routes:
                lines.extend([
                    f"Route: {route.get('dst', 'N/A')}",
                    f"  Gateway: {route.get('gateway', 'N/A')}",
                    f"  Interface: {route.get('interface', 'N/A')}",
                    f"  Distance: {route.get('distance', 'N/A')}",
                    f"  Priority: {route.get('priority', 'N/A')}",
                ])
                
                if route.get("status"):
                    lines.append(f"  Status: {route['status']}")
                
                if route.get("type"):
                    lines.append(f"  Type: {route['type']}")
                
                lines.append("")
        else:
            lines.append("No routes found")
        
        return "\n".join(lines)
    
    @staticmethod
    def static_routes(routes_data: Dict[str, Any]) -> str:
        """Format static routes list.
        
        Args:
            routes_data: Static routes response from FortiGate API
            
        Returns:
            Formatted static routes information
        """
        lines = ["Static Routes", ""]
        
        if "results" in routes_data and routes_data["results"]:
            routes = routes_data["results"]
            
            for route in routes:
                status = "Enabled" if route.get("status") == "enable" else "Disabled"
                
                lines.extend([
                    f"Route {route.get('seq-num', 'N/A')} ({status})",
                    f"  Destination: {route.get('dst', '0.0.0.0/0')}",
                    f"  Gateway: {route.get('gateway', 'N/A')}",
                    f"  Device: {route.get('device', 'N/A')}",
                    f"  Distance: {route.get('distance', 'N/A')}",
                ])
                
                if route.get("comment"):
                    lines.append(f"  Comment: {route['comment']}")
                
                lines.append("")
            

                
        else:
            lines.append("No static routes found")
        
        return "\n".join(lines)
    
    @staticmethod
    def interfaces(interfaces_data: Dict[str, Any]) -> str:
        """Format interfaces list.
        
        Args:
            interfaces_data: Interfaces response from FortiGate API
            
        Returns:
            Formatted interfaces information
        """
        lines = ["Network Interfaces", ""]
        
        if "results" in interfaces_data and interfaces_data["results"]:
            interfaces = interfaces_data["results"]
            
            for interface in interfaces:
                status = "Up" if interface.get("status") == "up" else "Down"
                
                lines.extend([
                    f"Interface: {interface.get('name', 'Unnamed')} ({status})",
                    f"  Type: {interface.get('type', 'unknown')}",
                    f"  Mode: {interface.get('mode', 'unknown')}",
                ])
                
                if interface.get("ip"):
                    lines.append(f"  IP: {interface['ip']}")
                if interface.get("alias"):
                    lines.append(f"  Alias: {interface['alias']}")
                
                lines.append("")
            

                
        else:
            lines.append("No interfaces found")
        
        return "\n".join(lines)
    
    @staticmethod
    def vdoms(vdoms_data: Dict[str, Any]) -> str:
        """Format VDOMs list.
        
        Args:
            vdoms_data: VDOMs response from FortiGate API
            
        Returns:
            Formatted VDOMs information
        """
        lines = ["Virtual Domains (VDOMs)", ""]
        
        if "results" in vdoms_data and vdoms_data["results"]:
            vdoms = vdoms_data["results"]
            
            for vdom in vdoms:
                enabled = "Yes" if vdom.get("enabled") else "No"
                
                lines.extend([
                    f"VDOM: {vdom.get('name', 'Unnamed')} (Enabled: {enabled})",
                ])
                
                if vdom.get("comments"):
                    lines.append(f"  Comments: {vdom['comments']}")
                
                lines.append("")
                
        else:
            lines.append("No VDOMs found")
        
        return "\n".join(lines)
    
    @staticmethod
    def operation_result(operation: str, device_id: str, success: bool, 
                        details: Optional[str] = None, error: Optional[str] = None) -> str:
        """Format operation result.
        
        Args:
            operation: Operation name
            device_id: Target device ID
            success: Whether operation succeeded
            details: Additional details about the operation
            error: Error message if operation failed
            
        Returns:
            Formatted operation result
        """
        status = "SUCCESS" if success else "FAILED"
        
        lines = [
            f"Operation {status}",
            f"  Operation: {operation}",
            f"  Device: {device_id}",
            f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ""
        ]
        
        if success and details:
            lines.extend([
                "Details:",
                f"  {details}",
                ""
            ])
        elif not success and error:
            lines.extend([
                "Error:",
                f"  {error}",
                ""
            ])
        
        return "\n".join(lines)
    
    @staticmethod
    def health_status(status: str, details: Dict[str, Any]) -> str:
        """Format health check status.
        
        Args:
            status: Overall health status
            details: Health check details
            
        Returns:
            Formatted health status
        """
        lines = [
            "FortiGate MCP Server Health",
            f"  Status: {status.upper()}",
            f"  Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ""
        ]
        
        if details.get("registered_devices") is not None:
            lines.append(f"  Registered Devices: {details['registered_devices']}")
        
        if details.get("server_version"):
            lines.append(f"  Server Version: {details['server_version']}")
        
        if details.get("uptime"):
            lines.append(f"  Uptime: {details['uptime']}")

        failed_devices = details.get("failed_devices")
        if failed_devices:
            lines.append(f"  Failed Devices: {len(failed_devices)}")
            for device_id, error in failed_devices.items():
                lines.append(f"    - {device_id}: {error}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Shared helpers for the extended tool surface
    # ------------------------------------------------------------------

    @staticmethod
    def _results_by_name(data: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Index a FortiOS list response by its ``name`` field (empty when absent)."""
        if not data or not isinstance(data.get("results"), list):
            return {}
        return {item["name"]: item for item in data["results"] if isinstance(item, dict) and "name" in item}

    @staticmethod
    def _names(items: Any) -> list:
        """Extract ``name`` values from a FortiOS member list (dicts or strings)."""
        names = []
        for item in items or []:
            if isinstance(item, dict) and "name" in item:
                names.append(str(item["name"]))
            elif isinstance(item, str):
                names.append(item)
        return names

    @staticmethod
    def _render_address_value(addr: Optional[Dict[str, Any]]) -> str:
        """One-line rendering of an address object's value."""
        if not addr:
            return "Not resolved"
        if addr.get("subnet"):
            return str(addr["subnet"])
        if addr.get("start-ip") and addr.get("end-ip"):
            return f"{addr['start-ip']} - {addr['end-ip']}"
        if addr.get("fqdn"):
            return f"fqdn {addr['fqdn']}"
        if addr.get("type") == "interface-subnet":
            return f"interface-subnet {addr.get('interface', '')}".strip()
        if addr.get("type") == "geography":
            return f"geography {addr.get('country', '')}".strip()
        if addr.get("macaddr"):
            return "mac " + ", ".join(FortiGateTemplates._names(addr.get("macaddr")))
        return str(addr.get("type", "unknown"))

    @staticmethod
    def _render_service_value(svc: Optional[Dict[str, Any]]) -> str:
        """One-line rendering of a service object's ports/protocol."""
        if not svc:
            return "Not resolved"
        parts = []
        if svc.get("tcp-portrange"):
            parts.append(f"TCP {svc['tcp-portrange']}")
        if svc.get("udp-portrange"):
            parts.append(f"UDP {svc['udp-portrange']}")
        if svc.get("sctp-portrange"):
            parts.append(f"SCTP {svc['sctp-portrange']}")
        if parts:
            return ", ".join(parts)
        protocol = str(svc.get("protocol", "unknown")).upper()
        if svc.get("protocol-number") not in (None, 0, "0"):
            return f"{protocol} (protocol {svc['protocol-number']})"
        return protocol

    @staticmethod
    def _fmt_epoch(value: Any) -> str:
        """Render an epoch-seconds value as local time, passing other values through."""
        try:
            return datetime.fromtimestamp(int(value)).strftime("%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError, OSError, OverflowError):
            return str(value)

    @staticmethod
    def _fmt_bytes(value: Any) -> str:
        try:
            n = float(value)
        except (TypeError, ValueError):
            return str(value)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if n < 1024 or unit == "TB":
                return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
            n /= 1024
        return str(value)

    @staticmethod
    def address_groups(groups_data: Dict[str, Any]) -> str:
        """Format the address group list."""
        lines = ["Address Groups", ""]
        results = groups_data.get("results") if isinstance(groups_data, dict) else None
        if not results:
            lines.append("No address groups found")
            return "\n".join(lines)
        for grp in results:
            members = FortiGateTemplates._names(grp.get("member", []))
            lines.append(f"Address Group: {grp.get('name', 'Unnamed')} ({len(members)} members)")
            if members:
                lines.append(f"  Members: {', '.join(members)}")
            excluded = FortiGateTemplates._names(grp.get("exclude-member", []))
            if grp.get("exclude") == "enable" and excluded:
                lines.append(f"  Excluded: {', '.join(excluded)}")
            if grp.get("comment"):
                lines.append(f"  Comment: {grp['comment']}")
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def address_group_detail(group: Dict[str, Any], address_objects: Optional[Dict[str, Any]] = None,
                             address_groups: Optional[Dict[str, Any]] = None) -> str:
        """Format one address group with every member resolved to its value."""
        addr_dict = FortiGateTemplates._results_by_name(address_objects)
        grp_dict = FortiGateTemplates._results_by_name(address_groups)
        members = FortiGateTemplates._names(group.get("member", []))
        lines = [
            f"Address Group: {group.get('name', 'Unnamed')}",
            f"  Type: {group.get('type', 'default')}",
            f"  Members: {len(members)}",
        ]
        if group.get("comment"):
            lines.append(f"  Comment: {group['comment']}")
        if group.get("uuid"):
            lines.append(f"  UUID: {group['uuid']}")
        lines.extend(["", "Resolved Members"])
        for member in members:
            if member in grp_dict:
                nested = FortiGateTemplates._names(grp_dict[member].get("member", []))
                lines.append(f"  {member}: nested group ({len(nested)} members: {', '.join(nested)})")
            else:
                lines.append(f"  {member}: {FortiGateTemplates._render_address_value(addr_dict.get(member))}")
        excluded = FortiGateTemplates._names(group.get("exclude-member", []))
        if group.get("exclude") == "enable" and excluded:
            lines.extend(["", f"Excluded Members: {', '.join(excluded)}"])
        return "\n".join(lines)

    @staticmethod
    def service_groups(groups_data: Dict[str, Any], service_objects: Optional[Dict[str, Any]] = None) -> str:
        """Format the service group list, resolving member ports when possible."""
        svc_dict = FortiGateTemplates._results_by_name(service_objects)
        lines = ["Service Groups", ""]
        results = groups_data.get("results") if isinstance(groups_data, dict) else None
        if not results:
            lines.append("No service groups found")
            return "\n".join(lines)
        for grp in results:
            members = FortiGateTemplates._names(grp.get("member", []))
            lines.append(f"Service Group: {grp.get('name', 'Unnamed')} ({len(members)} members)")
            for member in members:
                if svc_dict:
                    lines.append(f"  {member}: {FortiGateTemplates._render_service_value(svc_dict.get(member))}")
                else:
                    lines.append(f"  {member}")
            if grp.get("comment"):
                lines.append(f"  Comment: {grp['comment']}")
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def dhcp_servers(servers_data: Dict[str, Any]) -> str:
        """Format DHCP server configuration including reservations."""
        lines = ["DHCP Servers", ""]
        results = servers_data.get("results") if isinstance(servers_data, dict) else None
        if not results:
            lines.append("No DHCP servers configured")
            return "\n".join(lines)
        for srv in results:
            ranges = [f"{r.get('start-ip')} - {r.get('end-ip')}" for r in srv.get("ip-range", []) if isinstance(r, dict)]
            dns = [srv.get(k) for k in ("dns-server1", "dns-server2", "dns-server3") if srv.get(k) not in (None, "", "0.0.0.0")]
            lines.extend([
                f"DHCP Server ID {srv.get('id')}: interface {srv.get('interface', '?')} ({'Enabled' if srv.get('status') == 'enable' else 'Disabled'})",
                f"  Range: {', '.join(ranges) or 'N/A'}",
                f"  Gateway/Netmask: {srv.get('default-gateway', 'N/A')} / {srv.get('netmask', 'N/A')}",
                f"  DNS: {', '.join(dns) if dns else srv.get('dns-service', 'N/A')}",
                f"  Lease Time: {srv.get('lease-time', 'N/A')} s",
            ])
            reservations = [r for r in srv.get("reserved-address", []) if isinstance(r, dict)]
            lines.append(f"  Reservations: {len(reservations)}")
            for res in reservations:
                desc = f"  ({res['description']})" if res.get("description") else ""
                lines.append(f"    [{res.get('id')}] {res.get('ip')}  {res.get('mac')}  {res.get('action', 'reserved')}{desc}")
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def dhcp_leases(leases_data: Dict[str, Any], interface: Optional[str] = None) -> str:
        """Format active DHCP leases."""
        results = leases_data.get("results") if isinstance(leases_data, dict) else None
        results = [lease for lease in (results or []) if isinstance(lease, dict)]
        if interface:
            results = [lease for lease in results if lease.get("interface") == interface]
        title = f"DHCP Leases ({len(results)})" + (f" on {interface}" if interface else "")
        lines = [title, ""]
        if not results:
            lines.append("No active leases")
            return "\n".join(lines)
        results.sort(key=lambda lease: (str(lease.get("interface", "")), str(lease.get("ip", ""))))
        for lease in results:
            flag = " [reserved]" if lease.get("reserved") else ""
            lines.append(
                f"  {str(lease.get('ip', '')):16s} {str(lease.get('mac', '')):18s} "
                f"{str(lease.get('hostname') or '-'):24s} {str(lease.get('interface', '')):16s} "
                f"{str(lease.get('status', ''))}{flag}  expires {FortiGateTemplates._fmt_epoch(lease.get('expire_time'))}"
            )
        return "\n".join(lines)

    # Best-effort FortiGuard application category names (IDs are stable across
    # FortiOS releases; unknown IDs are shown numerically).
    APP_CATEGORY_NAMES = {
        2: "P2P", 3: "VoIP", 5: "Video/Audio", 6: "Proxy", 7: "Remote.Access", 8: "Game",
        12: "General.Interest", 15: "Network.Service", 17: "Update", 19: "Email",
        21: "Storage.Backup", 22: "Business", 23: "Social.Media", 25: "Web.Client",
        26: "Industrial", 28: "Collaboration", 29: "Cloud.IT", 30: "Mobile",
        31: "Unknown Applications", 32: "Botnet",
    }

    @staticmethod
    def security_profiles(profile_type: str, profiles_data: Dict[str, Any]) -> str:
        """Format a list of security profiles of one type."""
        lines = [f"Security Profiles: {profile_type}", ""]
        results = profiles_data.get("results") if isinstance(profiles_data, dict) else None
        if not results:
            lines.append("No profiles found")
            return "\n".join(lines)
        for prof in results:
            lines.append(f"Profile: {prof.get('name', 'Unnamed')}")
            if prof.get("comment"):
                lines.append(f"  Comment: {prof['comment']}")
            if profile_type == "application":
                entries = prof.get("entries", []) or []
                actions: Dict[str, int] = {}
                for entry in entries:
                    actions[entry.get("action", "?")] = actions.get(entry.get("action", "?"), 0) + 1
                summary = ", ".join(f"{k}: {v}" for k, v in sorted(actions.items()))
                lines.append(f"  Entries: {len(entries)}" + (f" ({summary})" if summary else ""))
                lines.append(f"  Other/Unknown apps: {prof.get('other-application-action', '?')}/{prof.get('unknown-application-action', '?')}")
            elif profile_type == "webfilter":
                filters = (prof.get("ftgd-wf") or {}).get("filters", []) or []
                blocked = sum(1 for f in filters if f.get("action") == "block")
                lines.append(f"  FortiGuard categories: {len(filters)} (block: {blocked})")
                if prof.get("feature-set"):
                    lines.append(f"  Feature Set: {prof['feature-set']}")
            elif profile_type == "ips":
                lines.append(f"  Entries: {len(prof.get('entries', []) or [])}")
            elif profile_type == "antivirus":
                lines.append(f"  Feature Set: {prof.get('feature-set', 'N/A')}")
            elif profile_type == "ssl-ssh":
                lines.append(f"  Inspection: {((prof.get('https') or {}).get('status', 'N/A'))} (https)")
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def security_profile_detail(profile_type: str, profile: Dict[str, Any],
                                app_names: Optional[Dict[int, Dict[str, Any]]] = None) -> str:
        """Format one security profile in depth."""
        lines = [f"Security Profile ({profile_type}): {profile.get('name', 'Unnamed')}"]
        if profile.get("comment"):
            lines.append(f"  Comment: {profile['comment']}")
        app_names = app_names or {}
        if profile_type == "application":
            lines.extend([
                f"  Other applications: {profile.get('other-application-action', '?')} (log {profile.get('other-application-log', '?')})",
                f"  Unknown applications: {profile.get('unknown-application-action', '?')} (log {profile.get('unknown-application-log', '?')})",
                f"  Deep inspection: {profile.get('deep-app-inspection', '?')}",
                "", "Entries (evaluated in order)",
            ])
            for entry in profile.get("entries", []) or []:
                cats = [int(c["id"]) for c in entry.get("category", []) if isinstance(c, dict) and c.get("id") is not None]
                apps = [int(a["id"]) for a in entry.get("application", []) if isinstance(a, dict) and a.get("id") is not None]
                risks = [str(r.get("level")) for r in entry.get("risk", []) if isinstance(r, dict)]
                scope = []
                if cats:
                    scope.append("categories: " + ", ".join(
                        f"{c} ({FortiGateTemplates.APP_CATEGORY_NAMES[c]})" if c in FortiGateTemplates.APP_CATEGORY_NAMES else str(c)
                        for c in cats))
                if apps:
                    scope.append("applications: " + ", ".join(
                        f"{app_names[a].get('name', a)} [{a}]" if a in app_names else str(a) for a in apps))
                if risks:
                    scope.append("risk: " + ", ".join(risks))
                if not scope:
                    scope.append("all applications")
                lines.append(f"  [{entry.get('id')}] {str(entry.get('action', '?')).upper()}  log={entry.get('log', '?')}  " + "; ".join(scope))
        elif profile_type == "webfilter":
            ftgd = profile.get("ftgd-wf") or {}
            filters = ftgd.get("filters", []) or []
            lines.extend([
                f"  Feature Set: {profile.get('feature-set', 'N/A')}",
                f"  URL filter table: {(profile.get('web') or {}).get('urlfilter-table', 0)}",
                f"  FortiGuard options: {ftgd.get('options', '')}",
                "", f"FortiGuard Category Actions ({len(filters)})",
            ])
            by_action: Dict[str, list] = {}
            for f in filters:
                by_action.setdefault(str(f.get("action", "?")), []).append(str(f.get("category")))
            for action, category_ids in sorted(by_action.items()):
                lines.append(f"  {action}: {', '.join(category_ids)}")
        else:
            lines.append("")
            for key, value in profile.items():
                if key in ("name", "comment", "q_origin_key") or key.startswith("fabric-"):
                    continue
                if isinstance(value, (str, int, float)) and value not in ("", None):
                    lines.append(f"  {key}: {value}")
                elif isinstance(value, list) and value:
                    lines.append(f"  {key}: {len(value)} entries")
        return "\n".join(lines)

    @staticmethod
    def ipsec_tunnels(tunnels_data: Dict[str, Any]) -> str:
        """Format IPsec tunnel status."""
        lines = ["IPsec Tunnels", ""]
        results = tunnels_data.get("results") if isinstance(tunnels_data, dict) else None
        if not results:
            lines.append("No IPsec tunnels configured")
            return "\n".join(lines)
        for tun in results:
            phase2 = [p for p in tun.get("proxyid", []) if isinstance(p, dict)]
            up = sum(1 for p in phase2 if p.get("status") == "up")
            dialup = tun.get("rgwy") in (None, "", "0.0.0.0")
            if dialup:
                state = f"dialup ({tun.get('connection_count', 0)} connected)" if tun.get("connection_count") is not None else "dialup"
            elif phase2:
                state = "UP" if up == len(phase2) else ("PARTIAL" if up else "DOWN")
            else:
                state = "DOWN"
            lines.append(f"Tunnel: {tun.get('name', '?')}  [{state}]")
            if tun.get("comments"):
                lines.append(f"  Comment: {tun['comments']}")
            if not dialup:
                lines.append(f"  Remote Gateway: {tun.get('rgwy')}")
            lines.append(f"  Traffic: in {FortiGateTemplates._fmt_bytes(tun.get('incoming_bytes', 0))}, out {FortiGateTemplates._fmt_bytes(tun.get('outgoing_bytes', 0))}")
            for p in phase2:
                src = ", ".join(s.get("subnet", str(s)) if isinstance(s, dict) else str(s) for s in p.get("proxy_src", []))
                dst = ", ".join(d.get("subnet", str(d)) if isinstance(d, dict) else str(d) for d in p.get("proxy_dst", []))
                lines.append(f"  Phase2 {p.get('p2name', '?')}: {str(p.get('status', '?')).upper()}  {src or '-'} -> {dst or '-'}  expires in {p.get('expire', '?')} s")
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _generic_records(title: str, records_data: Any, preferred: list, empty_text: str) -> str:
        """Render a list of dict records: preferred keys first, then other scalars."""
        results = records_data.get("results") if isinstance(records_data, dict) else records_data
        if isinstance(results, dict):
            results = [results]
        results = [r for r in (results or []) if isinstance(r, dict)]
        lines = [f"{title} ({len(results)})", ""]
        if not results:
            lines.append(empty_text)
            return "\n".join(lines)
        for rec in results:
            parts = []
            for key in preferred:
                if rec.get(key) not in (None, "", [], {}):
                    parts.append(f"{key}={rec[key]}")
            for key, value in rec.items():
                if key in preferred or key == "q_origin_key" or key.startswith("fabric-"):
                    continue
                if isinstance(value, (str, int, float, bool)) and value not in ("", None, False, 0):
                    parts.append(f"{key}={value}")
            lines.append("  " + "  ".join(parts[:14]))
        return "\n".join(lines)

    @staticmethod
    def ssl_vpn_sessions(sessions_data: Dict[str, Any]) -> str:
        return FortiGateTemplates._generic_records(
            "SSL-VPN Sessions", sessions_data,
            ["user_name", "remote_host", "last_login_time", "duration", "two_factor_auth"],
            "No active SSL-VPN sessions",
        )

    @staticmethod
    def local_users(users_data: Dict[str, Any]) -> str:
        results = users_data.get("results") if isinstance(users_data, dict) else None
        lines = [f"Local Users ({len(results or [])})", ""]
        if not results:
            lines.append("No local users")
            return "\n".join(lines)
        for user in results:
            extras = []
            if user.get("two-factor") not in (None, "", "disable"):
                extras.append(f"2FA={user['two-factor']}")
            if user.get("email-to"):
                extras.append(f"email={user['email-to']}")
            if user.get("ldap-server"):
                extras.append(f"ldap={user['ldap-server']}")
            lines.append(f"  {str(user.get('name', '?')):28s} {str(user.get('status', '?')):8s} type={user.get('type', '?')}" + ("  " + " ".join(extras) if extras else ""))
        return "\n".join(lines)

    @staticmethod
    def user_groups(groups_data: Dict[str, Any]) -> str:
        results = groups_data.get("results") if isinstance(groups_data, dict) else None
        lines = [f"User Groups ({len(results or [])})", ""]
        if not results:
            lines.append("No user groups")
            return "\n".join(lines)
        for grp in results:
            members = FortiGateTemplates._names(grp.get("member", []))
            lines.append(f"Group: {grp.get('name', '?')}  type={grp.get('group-type', '?')}  members={len(members)}")
            if members:
                lines.append(f"  Members: {', '.join(members)}")
            matches = [f"{m.get('server-name')}:{m.get('group-name')}" for m in grp.get("match", []) if isinstance(m, dict)]
            if matches:
                lines.append(f"  Remote matches: {', '.join(matches)}")
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def auth_sessions(sessions_data: Dict[str, Any]) -> str:
        return FortiGateTemplates._generic_records(
            "Authenticated Firewall Users", sessions_data,
            ["username", "src_ip", "method", "duration_secs", "expiry_secs", "traffic_vol_bytes"],
            "No authenticated firewall users",
        )

    @staticmethod
    def resource_usage(usage_data: Dict[str, Any]) -> str:
        results = usage_data.get("results") if isinstance(usage_data, dict) else None
        lines = ["System Resource Usage", ""]
        if not isinstance(results, dict):
            lines.append("No resource data")
            return "\n".join(lines)
        labels = [("cpu", "CPU %"), ("mem", "Memory %"), ("disk", "Disk %"), ("session", "Sessions (IPv4)"),
                  ("session6", "Sessions (IPv6)"), ("setuprate", "Session setup rate/s"), ("npu_session", "NPU sessions")]
        for key, label in labels:
            entries = results.get(key)
            if isinstance(entries, list) and entries and isinstance(entries[0], dict):
                lines.append(f"  {label}: {entries[0].get('current', 'N/A')}")
        return "\n".join(lines)

    @staticmethod
    def sessions(sessions_data: Dict[str, Any]) -> str:
        results = sessions_data.get("results") if isinstance(sessions_data, dict) else None
        details = results.get("details") if isinstance(results, dict) else results
        details = [d for d in (details or []) if isinstance(d, dict)]
        lines = [f"Active Sessions ({len(details)} shown)", ""]
        if not details:
            lines.append("No matching sessions")
            return "\n".join(lines)
        for sess in details:
            nat = f" nat {sess['snaddr']}:{sess.get('snport', '')}" if sess.get("snaddr") else ""
            lines.append(
                f"  {str(sess.get('proto', '?')):4s} {sess.get('saddr', '?')}:{sess.get('sport', '')} ({sess.get('srcintf', '?')}) -> "
                f"{sess.get('daddr', '?')}:{sess.get('dport', '')} ({sess.get('dstintf', '?')})  policy {sess.get('policyid', '?')}"
                f"  {sess.get('duration', 0)}s  sent {FortiGateTemplates._fmt_bytes(sess.get('sentbyte', 0))} / rcvd {FortiGateTemplates._fmt_bytes(sess.get('rcvdbyte', 0))}{nat}"
            )
        return "\n".join(lines)

    @staticmethod
    def event_log(log_data: Dict[str, Any], category: str = "") -> str:
        results = log_data.get("results") if isinstance(log_data, dict) else None
        results = [r for r in (results or []) if isinstance(r, dict)]
        lines = [f"Event Log {category} ({len(results)} records)", ""]
        if not results:
            lines.append("No matching log records")
            return "\n".join(lines)
        for rec in results:
            who = rec.get("user") or rec.get("ui") or ""
            lines.append(
                f"  {rec.get('date', '')} {rec.get('time', '')}  {str(rec.get('level', '')):8s} {str(rec.get('logdesc') or rec.get('action') or rec.get('subtype', '')):40s}"
                + (f"  user={who}" if who else "")
                + (f"  msg: {rec['msg']}" if rec.get("msg") else "")
            )
        return "\n".join(lines)

    @staticmethod
    def utm_log(log_data: Dict[str, Any], log_type: str = "") -> str:
        results = log_data.get("results") if isinstance(log_data, dict) else None
        results = [r for r in (results or []) if isinstance(r, dict)]
        lines = [f"UTM Log {log_type} ({len(results)} records)", ""]
        if not results:
            lines.append("No matching log records")
            return "\n".join(lines)
        for rec in results:
            what = rec.get("hostname") or rec.get("url") or rec.get("attack") or rec.get("app") or rec.get("virus") or rec.get("qname") or rec.get("catdesc") or ""
            lines.append(
                f"  {rec.get('date', '')} {rec.get('time', '')}  {str(rec.get('action') or rec.get('eventtype', '?')):10s} "
                f"{rec.get('srcip', '?')} -> {rec.get('dstip', '?')}:{rec.get('dstport', '')}  {what}"
                + (f"  [{rec['catdesc']}]" if rec.get("catdesc") and what != rec.get("catdesc") else "")
                + (f"  policy {rec['policyid']}" if rec.get("policyid") is not None else "")
                + (f"  msg: {rec['msg']}" if rec.get("msg") else "")
            )
        return "\n".join(lines)

    @staticmethod
    def traffic_log(log_data: Dict[str, Any]) -> str:
        results = log_data.get("results") if isinstance(log_data, dict) else None
        results = [r for r in (results or []) if isinstance(r, dict)]
        lines = [f"Traffic Log ({len(results)} records)", ""]
        if not results:
            lines.append("No matching log records")
            return "\n".join(lines)
        for rec in results:
            policy = f"policy {rec.get('policyid', '?')}"
            if rec.get("policyname"):
                policy += f" ({rec['policyname']})"
            name = f" [{rec['srcname']}]" if rec.get("srcname") else ""
            lines.append(
                f"  {rec.get('date', '')} {rec.get('time', '')}  {str(rec.get('action', '?')):8s} "
                f"{rec.get('srcip', '?')}:{rec.get('srcport', '')}{name} ({rec.get('srcintf', '?')}) -> "
                f"{rec.get('dstip', '?')}:{rec.get('dstport', '')} ({rec.get('dstintf', '?')})  "
                f"{rec.get('service', rec.get('proto', '?'))}  {policy}  "
                f"sent {FortiGateTemplates._fmt_bytes(rec.get('sentbyte', 0))} / rcvd {FortiGateTemplates._fmt_bytes(rec.get('rcvdbyte', 0))}"
                + (f"  msg: {rec['msg']}" if rec.get("msg") else "")
            )
        return "\n".join(lines)
