"""Match terminal interfaces against the replay's VM/container inventory."""


def device_port(host, port):
    prefix = host + "/"
    return host, port[len(prefix):] if port.startswith(prefix) else port


def nic_inventory(entries):
    """Accept legacy unique port names and host-qualified interface records."""
    if not isinstance(entries, list) or not entries:
        raise ValueError("vm_nics must list the VM and container port names from the inventory")
    inventory = set()
    for item in entries:
        if isinstance(item, str) and item:
            inventory.add(item)
            continue
        if isinstance(item, dict):
            host, port = item.get("phy_device_ID"), item.get("port_name")
            if isinstance(host, str) and host and isinstance(port, str) and port:
                inventory.add(device_port(host, port))
                continue
        raise ValueError("VM NIC entries must be port names or {phy_device_ID, port_name} objects")
    return inventory


def ends_at_nic(event, vm_nics):
    # With a drop, out_port_name contains the sentinel "dropped". The ingress
    # port is the last observed interface of that packet.
    port = event["in_port_name"] if event["action"] == "drop" else event["out_port_name"]
    host, name = device_port(event["phy_device_ID"], port)
    return port in vm_nics or name in vm_nics or (host, name) in vm_nics
