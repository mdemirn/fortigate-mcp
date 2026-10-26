"""Network object management tools for FortiGate MCP."""
from typing import Dict, Any, List, Optional
from mcp.types import TextContent as Content
from .base import FortiGateTool

class NetworkTools(FortiGateTool):
    """Tools for FortiGate network object management."""
    
    def list_address_objects(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List address objects."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            addresses_data = api_client.get_address_objects(vdom=vdom)
            return self._format_response(addresses_data, "address_objects")
        except Exception as e:
            return self._handle_error("list address objects", device_id, e)
    
    def create_address_object(self, device_id: str, name: str, address_type: str, address: str,
                             vdom: Optional[str] = None) -> List[Content]:
        """Create address object."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name, address_type=address_type, address=address)

            address_data: Dict[str, Any] = {
                "name": name,
                "type": address_type,
            }
            # Map the single 'address' field to the FortiGate cmdb key the
            # given address_type actually expects -- previously every type
            # was force-fit into 'subnet', silently corrupting fqdn/iprange
            # objects (the 'address' value landed in the wrong key).
            if address_type in ("ipmask", "subnet"):
                address_data["subnet"] = address
            elif address_type == "fqdn":
                address_data["fqdn"] = address
            elif address_type == "iprange":
                if "-" in address:
                    start_ip, end_ip = address.split("-", 1)
                    address_data["start-ip"] = start_ip.strip()
                    address_data["end-ip"] = end_ip.strip()
                else:
                    address_data["start-ip"] = address
            else:
                # Best-effort fallback for any other/unknown type, preserving
                # prior behavior.
                address_data["subnet"] = address

            api_client = self._get_device_api(device_id)
            api_client.create_address_object(address_data, vdom=vdom)
            return self._format_operation_result("create address object", device_id, True, f"Address object '{name}' created successfully")
        except Exception as e:
            return self._handle_error("create address object", device_id, e)
    
    def create_address_object_from_payload(self, device_id: str, address_data: Dict[str, Any],
                                          vdom: Optional[str] = None) -> List[Content]:
        """Create address object from a full dict payload, preserving every documented field.

        Unlike create_address_object (which only accepts a single 'address'
        string field, structurally dropping end-ip/fqdn variants), this
        adapter forwards the entire address_data dict unchanged to the API
        layer: ipmask keeps 'subnet', iprange keeps BOTH 'start-ip' and
        'end-ip', fqdn keeps 'fqdn' (never remapped to 'subnet'), and
        'comment' passes through.
        """
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=address_data.get("name"), type=address_data.get("type"))

            api_client = self._get_device_api(device_id)
            api_client.create_address_object(address_data, vdom=vdom)
            return self._format_operation_result("create address object", device_id, True, f"Address object '{address_data.get('name')}' created successfully")
        except Exception as e:
            return self._handle_error("create address object", device_id, e)

    def create_service_object_from_payload(self, device_id: str, service_data: Dict[str, Any],
                                          vdom: Optional[str] = None) -> List[Content]:
        """Create service object from a full dict payload, preserving every documented field.

        Unlike create_service_object (which collapses tcp-portrange/
        udp-portrange into a single generic 'port' field and drops
        'comment'), this adapter forwards the entire service_data dict
        unchanged to the API layer: 'tcp-portrange' and 'udp-portrange' are
        preserved as separate keys (a payload may carry both), and
        'comment' passes through.
        """
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=service_data.get("name"), protocol=service_data.get("protocol"))

            api_client = self._get_device_api(device_id)
            api_client.create_service_object(service_data, vdom=vdom)
            return self._format_operation_result("create service object", device_id, True, f"Service object '{service_data.get('name')}' created successfully")
        except Exception as e:
            return self._handle_error("create service object", device_id, e)

    def list_service_objects(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List service objects."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            services_data = api_client.get_service_objects(vdom=vdom)
            return self._format_response(services_data, "service_objects")
        except Exception as e:
            return self._handle_error("list service objects", device_id, e)
    
    def create_service_object(self, device_id: str, name: str, service_type: str, protocol: str,
                             port: Optional[str] = None, vdom: Optional[str] = None) -> List[Content]:
        """Create service object."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name, service_type=service_type, protocol=protocol)

            service_data: Dict[str, Any] = {
                "name": name,
                "type": service_type,
                "protocol": protocol
            }

            if port:
                # FortiGate's cmdb/firewall.service/custom expects a
                # protocol-specific portrange field, not a generic 'port'
                # key -- map by protocol so the value actually lands where
                # FortiGate will read it.
                protocol_upper = protocol.upper()
                if protocol_upper == "TCP":
                    service_data["tcp-portrange"] = port
                elif protocol_upper == "UDP":
                    service_data["udp-portrange"] = port
                elif protocol_upper == "SCTP":
                    service_data["sctp-portrange"] = port
                else:
                    # Fallback for protocols with no known portrange key
                    # (e.g. combined "TCP/UDP/SCTP" or ICMP).
                    service_data["port"] = port

            api_client = self._get_device_api(device_id)
            api_client.create_service_object(service_data, vdom=vdom)
            return self._format_operation_result("create service object", device_id, True, f"Service object '{name}' created successfully")
        except Exception as e:
            return self._handle_error("create service object", device_id, e)
    
    # ------------------------------------------------------------------
    # Address / service object update + delete
    # ------------------------------------------------------------------

    def update_address_object(self, device_id: str, name: str, address_data: Dict[str, Any],
                              vdom: Optional[str] = None) -> List[Content]:
        """Update an existing address object (partial payload is merged by FortiOS)."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name, address_data=address_data)
            api_client = self._get_device_api(device_id)
            api_client.update_address_object(name, address_data, vdom=vdom)
            return self._format_operation_result("update address object", device_id, True, f"Address object '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update address object", device_id, e)

    def delete_address_object(self, device_id: str, name: str, vdom: Optional[str] = None) -> List[Content]:
        """Delete an address object (FortiOS refuses while a policy or group still references it)."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            api_client.delete_address_object(name, vdom=vdom)
            return self._format_operation_result("delete address object", device_id, True, f"Address object '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete address object", device_id, e)

    def update_service_object(self, device_id: str, name: str, service_data: Dict[str, Any],
                              vdom: Optional[str] = None) -> List[Content]:
        """Update an existing custom service object."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name, service_data=service_data)
            api_client = self._get_device_api(device_id)
            api_client.update_service_object(name, service_data, vdom=vdom)
            return self._format_operation_result("update service object", device_id, True, f"Service object '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update service object", device_id, e)

    def delete_service_object(self, device_id: str, name: str, vdom: Optional[str] = None) -> List[Content]:
        """Delete a custom service object."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            api_client.delete_service_object(name, vdom=vdom)
            return self._format_operation_result("delete service object", device_id, True, f"Service object '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete service object", device_id, e)

    # ------------------------------------------------------------------
    # Address groups
    # ------------------------------------------------------------------

    @staticmethod
    def _member_names(members: Any) -> List[str]:
        names: List[str] = []
        for item in members or []:
            if isinstance(item, dict) and item.get("name"):
                names.append(str(item["name"]))
            elif isinstance(item, str) and item.strip():
                names.append(item.strip())
        return names

    def _find_address_group(self, api_client: Any, name: str, vdom: Optional[str]) -> Dict[str, Any]:
        """Locate a group by exact name from the list endpoint.

        Looking the group up in the list (instead of a per-name GET) keeps the
        name out of the REST path entirely, so group names that FortiOS allows
        but validate_object_name rejects (e.g. "G Suite") still resolve for
        read-only use.
        """
        groups = api_client.get_address_groups(vdom=vdom)
        for grp in groups.get("results", []) or []:
            if isinstance(grp, dict) and grp.get("name") == name:
                return dict(grp)
        raise ValueError(f"Address group not found: {self._safe_id(name)}")

    def list_address_groups(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List address groups with their member names."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            groups = api_client.get_address_groups(vdom=vdom)
            return self._format_response(groups, "address_groups")
        except Exception as e:
            return self._handle_error("list address groups", device_id, e)

    def get_address_group_detail(self, device_id: str, name: str, vdom: Optional[str] = None) -> List[Content]:
        """Show one address group with every member resolved to its IP/range/FQDN."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            groups = api_client.get_address_groups(vdom=vdom)
            group = None
            for grp in groups.get("results", []) or []:
                if isinstance(grp, dict) and grp.get("name") == name:
                    group = grp
                    break
            if group is None:
                raise ValueError(f"Address group not found: {self._safe_id(name)}")
            try:
                address_objects = api_client.get_address_objects(vdom=vdom)
            except Exception:
                address_objects = None
            return self._format_response(group, "address_group_detail",
                                         address_objects=address_objects, address_groups=groups)
        except Exception as e:
            return self._handle_error("get address group detail", device_id, e)

    def create_address_group(self, device_id: str, name: str, members: List[str],
                             comment: Optional[str] = None, vdom: Optional[str] = None) -> List[Content]:
        """Create an address group from existing address object names."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            member_names = self._member_names(members)
            if not member_names:
                raise ValueError("members must contain at least one address object name")
            group_data: Dict[str, Any] = {"name": name, "member": [{"name": m} for m in member_names]}
            if comment:
                group_data["comment"] = comment
            api_client = self._get_device_api(device_id)
            api_client.create_address_group(group_data, vdom=vdom)
            return self._format_operation_result("create address group", device_id, True,
                                                 f"Address group '{name}' created with {len(member_names)} member(s)")
        except Exception as e:
            return self._handle_error("create address group", device_id, e)

    def add_address_group_members(self, device_id: str, name: str, members: List[str],
                                  vdom: Optional[str] = None) -> List[Content]:
        """Add address objects to an existing group (existing members are kept)."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            new_members = self._member_names(members)
            if not new_members:
                raise ValueError("members must contain at least one address object name")
            api_client = self._get_device_api(device_id)
            group = self._find_address_group(api_client, name, vdom)
            current = self._member_names(group.get("member", []))
            added = [m for m in new_members if m not in current]
            if not added:
                return self._format_operation_result("add address group members", device_id, True,
                                                     f"Address group '{name}' already contains: {', '.join(new_members)}")
            merged = current + added
            api_client.update_address_group(name, {"member": [{"name": m} for m in merged]}, vdom=vdom)
            return self._format_operation_result("add address group members", device_id, True,
                                                 f"Added {', '.join(added)} to address group '{name}' (now {len(merged)} members)")
        except Exception as e:
            return self._handle_error("add address group members", device_id, e)

    def remove_address_group_members(self, device_id: str, name: str, members: List[str],
                                     vdom: Optional[str] = None) -> List[Content]:
        """Remove address objects from a group. FortiOS requires at least one member to remain."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            to_remove = self._member_names(members)
            if not to_remove:
                raise ValueError("members must contain at least one address object name")
            api_client = self._get_device_api(device_id)
            group = self._find_address_group(api_client, name, vdom)
            current = self._member_names(group.get("member", []))
            removed = [m for m in to_remove if m in current]
            if not removed:
                return self._format_operation_result("remove address group members", device_id, True,
                                                     f"Address group '{name}' does not contain: {', '.join(to_remove)}")
            remaining = [m for m in current if m not in removed]
            if not remaining:
                raise ValueError(
                    "Removing these members would leave the group empty; FortiOS requires at least one member. "
                    "Delete the group with delete_address_group instead."
                )
            api_client.update_address_group(name, {"member": [{"name": m} for m in remaining]}, vdom=vdom)
            return self._format_operation_result("remove address group members", device_id, True,
                                                 f"Removed {', '.join(removed)} from address group '{name}' (now {len(remaining)} members)")
        except Exception as e:
            return self._handle_error("remove address group members", device_id, e)

    def delete_address_group(self, device_id: str, name: str, vdom: Optional[str] = None) -> List[Content]:
        """Delete an address group (FortiOS refuses while a policy still references it)."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            api_client.delete_address_group(name, vdom=vdom)
            return self._format_operation_result("delete address group", device_id, True, f"Address group '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete address group", device_id, e)

    # ------------------------------------------------------------------
    # Service groups (read-only)
    # ------------------------------------------------------------------

    def list_service_groups(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List service groups, resolving member services to ports."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            groups = api_client.get_service_groups(vdom=vdom)
            try:
                service_objects = api_client.get_service_objects(vdom=vdom)
            except Exception:
                service_objects = None
            return self._format_response(groups, "service_groups", service_objects=service_objects)
        except Exception as e:
            return self._handle_error("list service groups", device_id, e)

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for network tools.
        
        Returns:
            Dictionary with schema information
        """
        return {
            "name": "network_tools",
            "description": "FortiGate network object management tools",
            "operations": [
                {
                    "name": "list_address_objects",
                    "description": "List address objects",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "create_address_object",
                    "description": "Create address object",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "name", "type": "string", "required": True},
                        {"name": "address_type", "type": "string", "required": True},
                        {"name": "address", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "list_service_objects",
                    "description": "List service objects",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "create_service_object",
                    "description": "Create service object",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "name", "type": "string", "required": True},
                        {"name": "service_type", "type": "string", "required": True},
                        {"name": "protocol", "type": "string", "required": True},
                        {"name": "port", "type": "string", "required": False},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {"name": "update_address_object", "description": "Update address object",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "name", "type": "string", "required": True},
                                {"name": "address_data", "type": "object", "required": True},
                                {"name": "vdom", "type": "string", "required": False}]},
                {"name": "delete_address_object", "description": "Delete address object",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "name", "type": "string", "required": True},
                                {"name": "vdom", "type": "string", "required": False}]},
                {"name": "update_service_object", "description": "Update service object",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "name", "type": "string", "required": True},
                                {"name": "service_data", "type": "object", "required": True},
                                {"name": "vdom", "type": "string", "required": False}]},
                {"name": "delete_service_object", "description": "Delete service object",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "name", "type": "string", "required": True},
                                {"name": "vdom", "type": "string", "required": False}]},
                {"name": "list_address_groups", "description": "List address groups",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "vdom", "type": "string", "required": False}]},
                {"name": "get_address_group_detail", "description": "Get address group detail with resolved members",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "name", "type": "string", "required": True},
                                {"name": "vdom", "type": "string", "required": False}]},
                {"name": "create_address_group", "description": "Create address group",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "name", "type": "string", "required": True},
                                {"name": "members", "type": "array", "required": True},
                                {"name": "comment", "type": "string", "required": False},
                                {"name": "vdom", "type": "string", "required": False}]},
                {"name": "add_address_group_members", "description": "Add members to address group",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "name", "type": "string", "required": True},
                                {"name": "members", "type": "array", "required": True},
                                {"name": "vdom", "type": "string", "required": False}]},
                {"name": "remove_address_group_members", "description": "Remove members from address group",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "name", "type": "string", "required": True},
                                {"name": "members", "type": "array", "required": True},
                                {"name": "vdom", "type": "string", "required": False}]},
                {"name": "delete_address_group", "description": "Delete address group",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "name", "type": "string", "required": True},
                                {"name": "vdom", "type": "string", "required": False}]},
                {"name": "list_service_groups", "description": "List service groups",
                 "parameters": [{"name": "device_id", "type": "string", "required": True},
                                {"name": "vdom", "type": "string", "required": False}]}
            ]
        }
