#!/usr/bin/env python3
"""NORDNET Phase 4: safely add P2 and validate redundant MPLS L3VPN.

Default is offline render. --build changes GNS3 topology only, --apply
adds/updates P2 and PE backup interfaces, --verify tests live state.
--failover-test deliberately stops P1 and ALWAYS attempts to restart it.
"""
from __future__ import annotations
import argparse
import os
from datetime import datetime, timezone
from getpass import getpass
import ipaddress
import json
from pathlib import Path
import re
import sys
import time

import requests
import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from ios_console import command, console_host, open_console

BASE = Path(__file__).resolve().parent
EXISTING_NODES = {"PE1", "P1", "PE2", "CE-MUNI-HQ", "CE-MUNI-BR"}
EXPECTED_NODES = EXISTING_NODES | {"P2"}
P2_POSITION = (0, 250)
EXPECTED_LOOPBACK = {"PE1": "172.20.255.1", "PE2": "172.20.255.2", "P2": "172.20.255.4"}
VERIFY_COMMANDS = {
    "PE1": ["show ip ospf neighbor", "show mpls ldp neighbor", "show ip route 172.20.255.2", "show mpls forwarding-table", "show ip bgp vpnv4 all summary"],
    "PE2": ["show ip ospf neighbor", "show mpls ldp neighbor", "show ip route 172.20.255.1", "show mpls forwarding-table", "show ip bgp vpnv4 all summary"],
    "P1": ["show ip ospf neighbor", "show mpls ldp neighbor", "show mpls forwarding-table"],
    "P2": ["show ip ospf neighbor", "show mpls ldp neighbor", "show mpls forwarding-table"],
    "CE-MUNI-HQ": ["show ip bgp summary", "show ip route 10.11.10.0", "ping 10.11.10.1 source 10.10.10.1"],
    "CE-MUNI-BR": ["show ip bgp summary", "show ip route 10.10.10.0", "ping 10.10.10.1 source 10.11.10.1"],
}


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def norm_intf(name):
    return name.replace("GigabitEthernet", "Gi")


def validate_inventory(inv):
    assert inv["project"] == os.environ.get("NORDNET_TARGET_PROJECT", "NORDNET-Core-POC"), "Refusing to target an unrelated project"
    assert inv["compute"] == "vm", "Unexpected GNS3 compute"
    assert inv["ospf_process"] == 100 and inv["ospf_area"] == 0
    assert inv["p1_cost"] < inv["p2_cost"]
    assert set(inv["routers"]) == {"PE1", "PE2", "P2"}
    assert {n: r["loopback"] for n, r in inv["routers"].items()} == EXPECTED_LOOPBACK
    expected_new = {
        frozenset({("PE1", "Gi0/2"), ("P2", "Gi0/0")}),
        frozenset({("PE2", "Gi0/2"), ("P2", "Gi0/1")}),
    }
    got_new = {frozenset({(a, norm_intf(ai)), (b, norm_intf(bi))}) for a, ai, b, bi in inv["links_new"]}
    assert got_new == expected_new, "Backup links cannot be moved to other interfaces"
    assert len(inv["links_existing"]) == 4
    for name, r in inv["routers"].items():
        ipaddress.IPv4Address(r["loopback"])
        if name != "P2":
            assert norm_intf(r["backup_interface"]) == "Gi0/2"
            assert r["backup_address"] == ("172.20.0.9" if name == "PE1" else "172.20.0.14")
        else:
            assert [i["ip"] for i in r["interfaces"]] == ["172.20.0.10", "172.20.0.13"]
    # Hard-coded safety guards make accidental changes to the known working lab unlikely.
    return True


def render(inv):
    env = Environment(loader=FileSystemLoader(BASE / "templates"), undefined=StrictUndefined,
                      trim_blocks=True, lstrip_blocks=True, keep_trailing_newline=True)
    out = BASE / "generated"
    out.mkdir(exist_ok=True)
    for name in ("P2", "PE1", "PE2"):
        template = env.get_template("p2.j2" if name == "P2" else "pe.j2")
        content = template.render(router=inv["routers"][name], p2=inv["routers"]["P2"],
                                  ospf_process=inv["ospf_process"], ospf_area=inv["ospf_area"],
                                  p2_cost=inv["p2_cost"])
        (out / f"{name}.cfg").write_text(content, encoding="utf-8")
        print(f"Rendered generated/{name}.cfg")


class API:
    def __init__(self, url, username, password):
        self.base_url = url.rstrip("/")
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.headers.update({"Accept": "application/json"})

    def call(self, verb, path, body=None):
        result = self.session.request(verb, self.base_url + path, json=body, timeout=40)
        if not result.ok:
            raise RuntimeError(f"GNS3 {verb} {path}: HTTP {result.status_code} {result.text[:500]}")
        return result.json() if result.content else None


def project_info(api, inv):
    projects = [p for p in api.call("GET", "/v2/projects") if p.get("name") == inv["project"]]
    if len(projects) != 1:
        raise RuntimeError(f"Expected exactly one existing project {inv['project']!r}; refusing other projects")
    p = projects[0]
    path = "/v2/projects/" + p["project_id"]
    if p.get("status") != "opened":
        api.call("POST", path + "/open", {})
    computes = {c["compute_id"]: c for c in api.call("GET", "/v2/computes")}
    host = computes.get(inv["compute"])
    if not host or not host.get("connected") or "qemu" not in host.get("capabilities", {}).get("node_types", []):
        raise RuntimeError("The vm compute is disconnected or lacks QEMU support")
    return path, host["host"]


def nodes_by_name(api, path):
    nodes = api.call("GET", path + "/nodes")
    if len(nodes) != len({n["name"] for n in nodes}):
        raise RuntimeError("Duplicate device names; refusing changes")
    return {n["name"]: n for n in nodes}


def port_endpoint(node, name):
    matched = [p for p in node.get("ports", []) if norm_intf(p["name"]) == norm_intf(name)]
    if len(matched) != 1:
        raise RuntimeError(f"{node['name']}: missing or duplicate {name}; ports={ [p['name'] for p in node.get('ports', [])] }")
    p = matched[0]
    return {"node_id": node["node_id"], "adapter_number": p["adapter_number"], "port_number": p["port_number"]}


def key(ep):
    return ep["node_id"], ep["adapter_number"], ep["port_number"]


def pair(nodes, lnk):
    a, ai, b, bi = lnk
    return frozenset({key(port_endpoint(nodes[a], ai)), key(port_endpoint(nodes[b], bi))})


def validate_nodes(nodes, inv, can_be_missing_p2=True):
    if not EXISTING_NODES.issubset(nodes):
        raise RuntimeError(f"Missing existing Phase 3 devices: {sorted(EXISTING_NODES - set(nodes))}")
    extra = set(nodes) - EXPECTED_NODES
    if extra:
        raise RuntimeError(f"Unrecognised project devices; refusing to touch this project: {sorted(extra)}")
    if not can_be_missing_p2 and "P2" not in nodes:
        raise RuntimeError("P2 missing; run --build")
    for name, n in nodes.items():
        if n.get("compute_id") != inv["compute"] or n.get("node_type") != "qemu":
            raise RuntimeError(f"Unexpected device type or compute for {name}")
    for name in ("PE1", "PE2"):
        port_endpoint(nodes[name], "GigabitEthernet0/2")  # Four-adapter IOSv template suffices.


def build(api, path, inv, permit_change):
    nodes = nodes_by_name(api, path)
    validate_nodes(nodes, inv)
    if "P2" not in nodes:
        if not permit_change:
            raise RuntimeError("P2 is absent: run --build")
        candidates = [x for x in api.call("GET", "/v2/templates") if x.get("name") == inv["template_name"] and x.get("template_type") == "qemu"]
        if len(candidates) != 1:
            raise RuntimeError("IOSv template name not found uniquely; verify template_name in inventory.yaml")
        tpl = candidates[0]
        if tpl.get("compute_id") not in (None, inv["compute"]):
            raise RuntimeError("IOSv template is assigned to the wrong compute")
        print("Creating P2 using the existing Cisco IOSv template ...")
        api.call("POST", path + "/templates/" + tpl["template_id"],
                 {"name": "P2", "compute_id": inv["compute"], "x": P2_POSITION[0], "y": P2_POSITION[1]})
        nodes = nodes_by_name(api, path)
    validate_nodes(nodes, inv, can_be_missing_p2=False)
    existing = api.call("GET", path + "/links")
    actual = {frozenset(key(ep) for ep in link["nodes"]) for link in existing}
    required_old = {pair(nodes, item) for item in inv["links_existing"]}
    required_new = {pair(nodes, item) for item in inv["links_new"]}
    if not required_old.issubset(actual):
        raise RuntimeError("An existing Phase 3 connection is missing or moved; refusing to proceed")
    if actual - (required_old | required_new):
        raise RuntimeError("Unexpected GNS3 links found; refusing to modify this project")
    used = set().union(*actual) if actual else set()
    for item in inv["links_new"]:
        a, ai, b, bi = item
        endpoints = [port_endpoint(nodes[a], ai), port_endpoint(nodes[b], bi)]
        link = frozenset(key(e) for e in endpoints)
        if link in actual:
            print(f"Exists: {a}:{ai} <-> {b}:{bi}")
            continue
        if not permit_change:
            raise RuntimeError(f"Link absent: {a}:{ai} <-> {b}:{bi}; run --build")
        if any(key(e) in used for e in endpoints):
            raise RuntimeError(f"Port collision: {a}:{ai} <-> {b}:{bi}")
        api.call("POST", path + "/links", {"nodes": endpoints})
        print(f"Created: {a}:{ai} <-> {b}:{bi}")
        used.update(link)
    return nodes_by_name(api, path)


def read_commands(node, host, commands):
    tn = open_console(console_host(node, host), node["console"])
    try:
        return {cmd: command(tn, cmd, timeout=50) for cmd in commands}
    finally:
        tn.close()


def iface_stanza(running, interface):
    lines = running.replace("\r", "").splitlines()
    target = "interface " + interface
    found = False
    out = []
    for ln in lines:
        if ln.strip() == target:
            found = True
            continue
        if found:
            if ln.startswith("!") or (ln and not ln.startswith(" ")):
                break
            out.append(ln.strip())
    if not found:
        raise RuntimeError(f"{interface} missing from show running-config")
    return out


def ensure_unused_or_expected(running, interface, expected_ip):
    stanza = iface_stanza(running, interface)
    ip_cmds = [x for x in stanza if x.startswith("ip address ")]
    allowed_ip = f"ip address {expected_ip} 255.255.255.252"
    if any(x != allowed_ip for x in ip_cmds):
        raise RuntimeError(f"Refusing overwrite: {interface} has unexpected IP config: {ip_cmds}")
    if any(x.startswith(("ip vrf forwarding", "vrf forwarding", "encapsulation dot1Q")) for x in stanza):
        raise RuntimeError(f"Refusing overwrite: {interface} has incompatible VRF/trunk configuration")


def push_config(node, host, name):
    tn = open_console(console_host(node, host), node["console"])
    try:
        running = command(tn, "show running-config", timeout=70)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_dir = BASE / "evidence" / "prechange"
        backup_dir.mkdir(parents=True, exist_ok=True)
        (backup_dir / f"{stamp}_{name}_running.txt").write_text(running, encoding="utf-8")
        if name == "P2":
            ensure_unused_or_expected(running, "GigabitEthernet0/0", "172.20.0.10")
            ensure_unused_or_expected(running, "GigabitEthernet0/1", "172.20.0.13")
        else:
            ip = "172.20.0.9" if name == "PE1" else "172.20.0.14"
            ensure_unused_or_expected(running, "GigabitEthernet0/2", ip)
        text = (BASE / "generated" / f"{name}.cfg").read_text(encoding="utf-8")
        print(f"Applying {name}: {len([x for x in text.splitlines() if x.strip() and not x.lstrip().startswith('!')])} commands")
        command(tn, "configure terminal")
        for item in text.splitlines():
            if item.strip() and not item.lstrip().startswith("!"):
                command(tn, item, timeout=35)
        command(tn, "end")
        command(tn, "write memory", timeout=70)
    finally:
        tn.close()


def ospf_full_peers(output):
    return set(re.findall(r"(?m)^\s*(172\.20\.255\.\d+)\s+\d+\s+FULL/", output))


def ldp_oper_peers(output):
    chunks = re.split(r"(?=\s*Peer LDP Ident:)", output)
    peers = set()
    for c in chunks:
        match = re.search(r"Peer LDP Ident:\s*(172\.20\.255\.\d+):0", c)
        if match and re.search(r"State:\s*Oper\b", c):
            peers.add(match.group(1))
    return peers


def bgp_established(output, neighbor):
    for ln in output.splitlines():
        fields = ln.split()
        if fields and fields[0] == neighbor and fields[-1].isdigit():
            return True
    return False


def ping_success(output):
    match = re.search(r"Success rate is\s+(\d+)\s+percent\s*\((\d+)/(\d+)\)", output)
    return bool(match and int(match.group(1)) == 100 and int(match.group(2)) == int(match.group(3)) and int(match.group(3)) > 0)


def new_evidence(kind, data, report):
    d = BASE / "evidence"
    d.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filepath = d / f"{stamp}_{kind}.txt"
    lines = []
    for device, cmd_dict in data.items():
        for cmd, output in cmd_dict.items():
            lines.append(f"\n\n===== {now()} :: {device} :: {cmd} =====\n{output}")
    filepath.write_text("".join(lines), encoding="utf-8")
    summary = d / f"{stamp}_{kind}.json"
    summary.write_text(json.dumps({"time_utc": now(), "type": kind, **report}, indent=2) + "\n", encoding="utf-8")
    print(f"Evidence: {filepath.relative_to(BASE)}, {summary.relative_to(BASE)}")


def baseline_checks(data, path="primary"):
    failures = []
    expected_ospf = {
        "PE1": {"172.20.255.3", "172.20.255.4"},
        "PE2": {"172.20.255.3", "172.20.255.4"},
        "P1": {"172.20.255.1", "172.20.255.2"},
        "P2": {"172.20.255.1", "172.20.255.2"},
    }
    for name, wanted in expected_ospf.items():
        ospf = ospf_full_peers(data[name]["show ip ospf neighbor"])
        ldp = ldp_oper_peers(data[name]["show mpls ldp neighbor"])
        if not wanted.issubset(ospf):
            failures.append(f"{name}: OSPF FULL peers {sorted(ospf)} expected {sorted(wanted)}")
        if not wanted.issubset(ldp):
            failures.append(f"{name}: LDP peers {sorted(ldp)} expected {sorted(wanted)}")
    next_hop = "172.20.0.2" if path == "primary" else "172.20.0.10"
    outbound = "GigabitEthernet0/0" if path == "primary" else "GigabitEthernet0/2"
    route = data["PE1"]["show ip route 172.20.255.2"]
    if next_hop not in route or outbound not in route:
        failures.append(f"PE1 is not using {path} path toward PE2 ({next_hop} via {outbound})")
    if not bgp_established(data["PE1"]["show ip bgp vpnv4 all summary"], "172.20.255.2"):
        failures.append("PE1->PE2 VPNv4 iBGP not established")
    if not bgp_established(data["PE2"]["show ip bgp vpnv4 all summary"], "172.20.255.1"):
        failures.append("PE2->PE1 VPNv4 iBGP not established")
    for ce in ("CE-MUNI-HQ", "CE-MUNI-BR"):
        ping = next(val for cmd, val in data[ce].items() if cmd.startswith("ping "))
        if not ping_success(ping):
            failures.append(f"{ce}: end-to-end ping failed")
    return failures


def run_verify(nodes, host, kind="phase4_baseline"):
    if any(n["status"] != "started" for n in nodes.values()):
        raise RuntimeError("All six nodes must be running before baseline verification")
    data = {}
    for name, cmds in VERIFY_COMMANDS.items():
        print(f"Collecting {name} verification commands ...")
        data[name] = read_commands(nodes[name], host, cmds)
    failures = baseline_checks(data)
    report = {"passed": not failures, "failures": failures, "p2_adjacencies": 2,
              "vpn_peers": 1, "customer_ping_directions": 2}
    new_evidence(kind, data, report)
    for x in failures:
        print(f"FAIL: {x}")
    if failures:
        raise RuntimeError(f"Phase 4 verification failed ({len(failures)} issues); see evidence folder")
    print("PASS: OSPF/LDP neighbours (four provider routers); primary path; VPNv4; both CE pings")
    return data


def poll_backup(nodes, host, seconds=120):
    print("Polling PE1 path to PE2 and municipal CE-to-CE reachability ...")
    deadline = time.monotonic() + seconds
    attempts = []
    while time.monotonic() < deadline:
        ts = time.monotonic()
        outputs = {"PE1": read_commands(nodes["PE1"], host, ["show ip route 172.20.255.2", "show mpls forwarding-table"]),
                   "CE-MUNI-HQ": read_commands(nodes["CE-MUNI-HQ"], host, ["ping 10.11.10.1 source 10.10.10.1"]),
                   "CE-MUNI-BR": read_commands(nodes["CE-MUNI-BR"], host, ["ping 10.10.10.1 source 10.11.10.1"])}
        route = outputs["PE1"]["show ip route 172.20.255.2"]
        backup = "172.20.0.10" in route and "GigabitEthernet0/2" in route
        lfib_lines = outputs["PE1"]["show mpls forwarding-table"].splitlines()
        mpls = any("172.20.255.2/32" in line and ("Gi0/2" in line or "GigabitEthernet0/2" in line)
                   for line in lfib_lines)
        pings = all(ping_success(next(iter(outputs[ce].values()))) for ce in ("CE-MUNI-HQ", "CE-MUNI-BR"))
        attempts.append({"seconds_after_stop_start": round(ts - (deadline - seconds), 1),
                         "backup_route": backup, "mpls_fec_present": mpls, "both_ce_pings_passed": pings})
        print(f"  T+{round(ts-(deadline-seconds),1)}s: backup route={backup}; MPLS FEC={mpls}; both pings={pings}")
        if backup and mpls and pings:
            return True, attempts, outputs
        time.sleep(3)
    return False, attempts, outputs if attempts else {}


def failover_test(api, path, nodes, compute_host, timeout, yes):
    if not yes:
        raise RuntimeError("This test STOPS P1. Re-run with --yes after saving your project")
    if nodes["P1"]["status"] != "started":
        raise RuntimeError("P1 must be running before the test")
    print("Checking healthy baseline before disrupting P1 ...")
    run_verify(nodes, compute_host, kind="phase4_failover_before")
    stop_attempted = False
    restore_ok = False
    started_at = now()
    attempts, outputs = [], {}
    success = False
    try:
        print("Stopping P1 through the GNS3 API — intentional service disturbance")
        stop_attempted = True
        api.call("POST", path + f"/nodes/{nodes['P1']['node_id']}/stop", {})
        success, attempts, outputs = poll_backup(nodes, compute_host, seconds=timeout)
    finally:
        # Restore P1 after success, failure or Ctrl+C. A forced process kill
        # cannot run finally; --restore is provided for that situation.
        if stop_attempted:
            print("Restoring P1 (automatic cleanup) ...")
            try:
                actual = nodes_by_name(api, path)["P1"]
                if actual["status"] != "started":
                    api.call("POST", path + f"/nodes/{nodes['P1']['node_id']}/start", {})
                restore_ok = True
                print("P1 is running or its start request was accepted; allow OSPF/LDP reconvergence.")
            except Exception as exc:
                print(f"CRITICAL: Automatic P1 restore failed: {exc}. Run --restore.", file=sys.stderr)
        new_evidence("phase4_failover_test", {"PE1": outputs.get("PE1", {}),
                    "CE-MUNI-HQ": outputs.get("CE-MUNI-HQ", {}),
                    "CE-MUNI-BR": outputs.get("CE-MUNI-BR", {})},
                    {"test_started_utc": started_at, "backup_recovery_observed": success,
                     "P1_stop_attempted": stop_attempted, "P1_restore_accepted": restore_ok,
                     "poll_samples": attempts,
                     "note": "Polling bounds recovery; it is not an exact OSPF convergence measurement."})
    if not restore_ok:
        raise RuntimeError("P1 may remain stopped. Use --restore and check GNS3 before continuing")
    return success


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--build", action="store_true", help="Add only P2 and its two new GNS3 links")
    group.add_argument("--apply", action="store_true", help="Build if needed, apply P2 and PE backup configs")
    group.add_argument("--verify", action="store_true", help="Collect and verify routing/CE reachability")
    group.add_argument("--failover-test", action="store_true", help="STOP P1, check VPN over P2, auto-restart P1")
    group.add_argument("--restore", action="store_true", help="Start P1 if it was left stopped")
    parser.add_argument("--yes", action="store_true", help="Confirm P1 shutdown for --failover-test")
    parser.add_argument("--timeout", type=int, default=120, help="Failover polling upper bound in seconds (default 120)")
    parser.add_argument("--url", default="http://127.0.0.1:3080")
    parser.add_argument("--user", default="admin")
    args = parser.parse_args()
    if args.timeout < 20 or args.timeout > 600:
        raise ValueError("--timeout must be between 20 and 600 seconds")
    inv = yaml.safe_load((BASE / "inventory.yaml").read_text(encoding="utf-8"))
    inv["project"] = os.environ.get("NORDNET_TARGET_PROJECT", "NORDNET-Core-POC")
    validate_inventory(inv)
    render(inv)
    mode = (args.build or args.apply or args.verify or args.failover_test or args.restore)
    if not mode:
        print("Render-only completed; no GNS3 or IOS changes. Inspect generated/*.cfg before applying.")
        return
    if (args.apply or args.verify or args.failover_test) and sys.version_info[:2] != (3, 12):
        raise RuntimeError("Console operations need Python 3.12 (telnetlib)")
    api = API(args.url, args.user, getpass("GNS3 controller API password: "))
    print("GNS3:", api.call("GET", "/v2/version").get("version"))
    path, compute_host = project_info(api, inv)
    nodes = build(api, path, inv, permit_change=args.build or args.apply)
    if args.build:
        print("P2 and backup links exist; no IOS config changed")
        return
    if args.apply:
        if any(nodes[n]["status"] != "started" for n in EXISTING_NODES):
            raise RuntimeError("Existing five routers must be running before --apply; start them in GNS3")
        if nodes["P2"]["status"] != "started":
            print("Starting P2 ...")
            api.call("POST", path + f"/nodes/{nodes['P2']['node_id']}/start", {})
            nodes = nodes_by_name(api, path)
        for name in ("P2", "PE1", "PE2"):
            print(f"Configuring {name} via GNS3 console ...")
            push_config(nodes[name], compute_host, name)
        print("Phase 4 deployment applied. Run --verify after OSPF and LDP converge.")
        return
    if args.restore:
        if nodes["P1"]["status"] == "started":
            print("P1 already started; nothing changed")
        else:
            api.call("POST", path + f"/nodes/{nodes['P1']['node_id']}/start", {})
            print("P1 restarted; allow OSPF/LDP to converge then run --verify")
        return
    if args.verify:
        run_verify(nodes, compute_host)
        return
    if args.failover_test:
        ok = failover_test(api, path, nodes, compute_host, args.timeout, args.yes)
        if not ok:
            raise RuntimeError("Backup was NOT fully verified within timeout; P1 restart requested; inspect evidence")
        print("PASS: Both municipal sites remain reachable over P2 after stopping P1; P1 restart requested")
        print("Run --verify after the preferred P1 path returns to confirm restoration")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, ValueError, KeyError, RuntimeError, requests.RequestException, KeyboardInterrupt) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
