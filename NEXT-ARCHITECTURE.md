# Remaining local milestones before external integration

This file is an implementation backlog, **not** a claim the features are deployed.

## Local service network (internal)
- Replace `PC-HQ-SVC` (currently a VPCS testing endpoint) or attach an additional Linux/Docker server on the HQ services VLAN 30.
- Provide DNS, optional DHCP, a simple internal HTTPS service, and logging. Use a real lightweight Linux system; VPCS cannot host these services.
- Verify clients use DNS and DHCP correctly; record service and failure tests.

## Shared-services VRF + inspected access (internal)
- Current PE1 and PE2 have all four virtual adapters occupied. Do not repurpose an occupied PE interface automatically.
- Options: create new 8-adapter PE appliances in a clean, reproducible new project; or convert P2 to a PE-capable role with new customer-facing service attachment and appropriate MP-BGP VPNv4 design.
- Attach SHARED VRF to a local service gateway, with a firewall/ACL and explicit return routes. Route-target imports without firewall rules are insufficient.
- Test application reachability and denied access to non-shared addresses.

## Management and local SOC (internal)
- Use the GNS3 controller/console as the existing management channel until a separate provider out-of-band management network is implemented.
- For a true OOB network, add spare interfaces to provider nodes via a planned rebuild and attach an isolated management Ethernet switch.
- Build a small syslog collector and incident-case logger locally; route management-plane telemetry to the collector, and test outages and buffering.
- Do not expose management Telnet/API endpoints or unprotected web dashboards to the Internet.

## Off-site integration (later, external boundary)
- Establish a strictly outbound VPN to an off-site VPS and forward selected logs or evidence. Use synthetic test data only.
- Add off-site backups and incident case synchronisation. Verify behaviour with the external link intentionally disabled.

## Why the staged execution still matters
A single `apply` command can drive all of these stages, but should **gate** on local network and service health. Otherwise an unrelated Docker/image or firewall problem could leave the validated MPLS core in an ambiguous state. Keep phase-specific scripts until each stage is proven, then consolidate to one orchestrator.
