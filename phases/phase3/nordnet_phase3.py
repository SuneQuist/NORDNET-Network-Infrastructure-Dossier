#!/usr/bin/env python3
"""NORDNET Phase 3: MUNI L3VPN, two new IOSv CEs, console-based provisioning.

Default: render-only. --build: add CE nodes/links. --apply: build + configure.
--verify: collect live evidence and run CE-to-CE ping tests (no changes).
Uses the GNS3 2.2 controller; Python 3.12 required for --apply/--verify.
"""
from __future__ import annotations

import argparse
import os
from datetime import datetime, timezone
from getpass import getpass
import ipaddress
from pathlib import Path
import re
import sys
import time
import warnings

import requests
import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined

BASE = Path(__file__).resolve().parent
REQUIRED = {"PE1", "P1", "PE2", "CE-MUNI-HQ", "CE-MUNI-BR"}
EXTRA_NODES = {"CE-MUNI-HQ": (-320, 260), "CE-MUNI-BR": (320, 260)}
DEPLOY = ("PE1", "PE2", "CE-MUNI-HQ", "CE-MUNI-BR")
CMD_ERROR = re.compile(r"(?im)^\s*%\s*(Invalid input|Incomplete command|Ambiguous command|Error|Unrecognized command)")
PROMPT = re.compile(r"^[A-Za-z0-9_.-]+(?:\([^()\n]+\))?[>#]$")


def norm_interface(name: str) -> str:
    return name.replace("GigabitEthernet", "Gi")


def validate_inventory(inv):
    if set(inv["routers"]) != REQUIRED - {"P1"}:
        raise ValueError("Inventory must describe PE1, PE2, CE-MUNI-HQ and CE-MUNI-BR")
    ips = set()
    for n, r in inv["routers"].items():
        for k in ("customer_ip", "customer_peer_ip"):
            ipaddress.IPv4Address(r[k])
        if r["customer_ip"] in ips:
            raise ValueError(f"Duplicate customer address on {n}")
        ips.add(r["customer_ip"])
        if r["role"] == "pe":
            ipaddress.IPv4Address(r["router_id"])
            if r["asn"] != inv["provider_asn"]:
                raise ValueError("PE ASN must be provider ASN")
        else:
            if ipaddress.IPv4Address(r["loopback"]) not in ipaddress.IPv4Network(r["lan_prefix"]):
                raise ValueError(f"{n} loopback outside LAN prefix")
            if r["lan_prefix"] == r["remote_lan_prefix"]:
                raise ValueError("Customer site LANs must differ")
    for peer_a, peer_b in (("PE1", "CE-MUNI-HQ"), ("PE2", "CE-MUNI-BR")):
        a, b = inv["routers"][peer_a], inv["routers"][peer_b]
        if a["customer_ip"] != b["customer_peer_ip"] or b["customer_ip"] != a["customer_peer_ip"]:
            raise ValueError(f"PE-CE peer IP mismatch: {peer_a}, {peer_b}")
        if a["customer_asn"] != b["asn"]:
            raise ValueError(f"PE-CE ASN mismatch: {peer_a}, {peer_b}")
        if a["allowed_prefix"] != b["lan_prefix"]:
            raise ValueError(f"PE ingress prefix policy mismatch for {peer_b}")
    for n, r in inv["routers"].items():
        if norm_interface(r["customer_interface"]) not in ("Gi0/0", "Gi0/1"):
            raise ValueError(f"Unexpected customer interface on {n}")
    if len({r["rd"] for r in inv["routers"].values() if r["role"] == "pe"}) != 2:
        raise ValueError("PE route distinguishers must be distinct")
    if len(inv["links"]) != 4:
        raise ValueError("Phase 3 expects four core/customer links")


def render(inv):
    env = Environment(loader=FileSystemLoader(BASE / "templates"), undefined=StrictUndefined,
                      trim_blocks=True, lstrip_blocks=True, keep_trailing_newline=True)
    out = BASE / "generated"
    out.mkdir(exist_ok=True)
    for name, router in inv["routers"].items():
        template = env.get_template(router["role"] + ".j2")
        content = template.render(name=name, router=router, provider_asn=inv["provider_asn"],
                                  vrf=inv["vrf"], route_target=inv["route_target"])
        dest = out / f"{name}.cfg"
        dest.write_text(content, encoding="utf-8")
        print(f"Rendered {dest}")


class Controller:
    def __init__(self, url, user, password):
        self.url = url.rstrip("/")
        self.s = requests.Session()
        self.s.auth = (user, password)
        self.s.headers["Accept"] = "application/json"

    def call(self, method, path, data=None):
        response = self.s.request(method, self.url + path, json=data, timeout=30)
        if not response.ok:
            raise RuntimeError(f"{method} {path}: HTTP {response.status_code} {response.text[:500]}")
        return response.json() if response.content else None


def find_project(api, inv):
    matches = [p for p in api.call("GET", "/v2/projects") if p["name"] == inv["project"]]
    if len(matches) != 1:
        raise RuntimeError(f"Expected one existing project {inv['project']!r}, found {len(matches)}")
    p = matches[0]
    base = f"/v2/projects/{p['project_id']}"
    if p.get("status") != "opened":
        api.call("POST", base + "/open", {})
    computes = {x["compute_id"]: x for x in api.call("GET", "/v2/computes")}
    compute = computes.get(inv["compute"])
    if not compute or not compute.get("connected"):
        raise RuntimeError(f"GNS3 compute {inv['compute']} is not connected")
    if "qemu" not in compute.get("capabilities", {}).get("node_types", []):
        raise RuntimeError("Compute has no QEMU capability")
    return base, compute["host"]


def get_nodes(api, base):
    nodes = api.call("GET", base + "/nodes")
    if len(nodes) != len({n["name"] for n in nodes}):
        raise RuntimeError("Duplicate node names detected; refusing changes")
    return {n["name"]: n for n in nodes}


def endpoint(node, interface):
    wanted = norm_interface(interface)
    ports = [p for p in node["ports"] if norm_interface(p["name"]) == wanted]
    if len(ports) != 1:
        raise RuntimeError(f"{node['name']} does not expose exactly one {interface}; available: {[p['name'] for p in node['ports']]}")
    p = ports[0]
    return {"node_id": node["node_id"], "adapter_number": p["adapter_number"], "port_number": p["port_number"]}


def ep_key(ep):
    return (ep["node_id"], ep["adapter_number"], ep["port_number"])


def expected_links(nodes, inv):
    return {frozenset((ep_key(endpoint(nodes[a], ai)), ep_key(endpoint(nodes[b], bi))))
            for a, ai, b, bi in inv["links"]}


def build(api, base, inv, make_changes):
    nodes = get_nodes(api, base)
    unknown = set(nodes) - REQUIRED
    if unknown:
        raise RuntimeError(f"Unexpected nodes found; refusing changes: {sorted(unknown)}")
    if not {"PE1", "P1", "PE2"}.issubset(nodes):
        raise RuntimeError("Phase 2 three-router core must already exist")
    for name, node in nodes.items():
        if node.get("compute_id") != inv["compute"] or node.get("node_type") != "qemu":
            raise RuntimeError(f"Unexpected node type/compute for {name}")
    templates = [t for t in api.call("GET", "/v2/templates")
                 if t.get("name") == inv["template_name"] and t.get("template_type") == "qemu"]
    if len(templates) != 1:
        raise RuntimeError(f"No unique QEMU template named {inv['template_name']!r}; change template_name in inventory.yaml")
    template = templates[0]
    if template.get("compute_id") not in (None, inv["compute"]):
        raise RuntimeError("IOSv template is assigned to wrong compute")
    for name, (x, y) in EXTRA_NODES.items():
        if name not in nodes:
            if not make_changes:
                raise RuntimeError(f"Missing {name}; run --build before --verify")
            print(f"Creating {name} from template {inv['template_name']!r}")
            nodes[name] = api.call("POST", f"{base}/templates/{template['template_id']}",
                                   {"name": name, "compute_id": inv["compute"], "x": x, "y": y})
    for name in REQUIRED:
        if nodes[name].get("node_type") != "qemu" or nodes[name].get("compute_id") != inv["compute"]:
            raise RuntimeError(f"Node {name} has unexpected compute/type")
    if set(nodes) != REQUIRED:
        raise RuntimeError("Topology has unexpected nodes")
    links = api.call("GET", base + "/links")
    current = {frozenset(ep_key(p) for p in link["nodes"]) for link in links}
    expected = expected_links(nodes, inv)
    unknown_links = current - expected
    if unknown_links:
        raise RuntimeError("Existing GNS3 links don't match the approved four-link topology")
    used = {ep for link in current for ep in link}
    for a, ai, b, bi in inv["links"]:
        epa, epb = endpoint(nodes[a], ai), endpoint(nodes[b], bi)
        pair = frozenset((ep_key(epa), ep_key(epb)))
        if pair in current:
            continue
        if not make_changes:
            raise RuntimeError(f"Missing link {a}:{ai}--{b}:{bi}")
        if ep_key(epa) in used or ep_key(epb) in used:
            raise RuntimeError(f"Port collision before linking {a}:{ai}--{b}:{bi}")
        api.call("POST", base + "/links", {"nodes": [epa, epb]})
        print(f"Created {a}:{ai} -- {b}:{bi}")
        used.update(pair)
    return get_nodes(api, base)


def _last_line(raw):
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
    text = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", text)
    return next((l.strip() for l in reversed(text.replace("\r", "").split("\n")) if l.strip()), "")


def recv_prompt(tn, timeout=35, first_boot=False):
    """Recover stable IOS prompt, including unsolicited %SYS and %LINEPROTO messages."""
    first = re.compile(r"Would you like to enter the initial configuration dialog\?\s*\[yes/no\]:?\s*$", re.I)
    enter = re.compile(r"Press (?:RETURN|ENTER) to get started!?", re.I)
    end = time.monotonic() + timeout
    last_rx = last_nudge = time.monotonic()
    buf = bytearray()
    nudges = 0
    last_action = None
    while time.monotonic() < end:
        try:
            chunk = tn.read_very_eager()
        except EOFError as exc:
            raise RuntimeError("Console disconnected") from exc
        now = time.monotonic()
        if chunk:
            buf.extend(chunk)
            last_rx = now
            if len(buf) > 2_000_000:
                raise RuntimeError("IOS flooded the console output")
        tail = _last_line(buf)
        if first.search(tail):
            if not first_boot:
                raise RuntimeError("Unexpected initial configuration dialog")
            if last_action != ("no", tail):
                tn.write(b"no\r\n")
                last_action = ("no", tail)
        elif enter.search(tail):
            if not first_boot:
                raise RuntimeError("Unexpected boot prompt")
            if last_action != ("enter", tail):
                tn.write(b"\r\n")
                last_action = ("enter", tail)
        elif tail.lower().endswith("password:") or re.search(r"\[yes/no\]:?$", tail, re.I):
            raise RuntimeError(f"Unexpected interactive IOS question: {tail}")
        elif PROMPT.fullmatch(tail) and now - last_rx >= 0.3:
            return buf.decode("utf-8", errors="replace")
        elif now - last_rx >= 0.8 and now - last_nudge >= 0.8:
            tn.write(b"\r\n")
            last_nudge = now
            nudges += 1
            if nudges >= 8:
                break
        time.sleep(0.06)
    raise RuntimeError(f"IOS prompt not recovered; tail={_last_line(buf)!r}")


def command(tn, cmd, timeout=35):
    tn.write(cmd.encode("ascii") + b"\r\n")
    out = recv_prompt(tn, timeout)
    if CMD_ERROR.search(out):
        raise RuntimeError(f"IOS rejected {cmd!r}: {out[-700:]}")
    return out


def console(host, port):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        import telnetlib  # Python 3.12 only; console access confined to lab
    deadline = time.monotonic() + 150
    last = None
    while time.monotonic() < deadline:
        tn = None
        try:
            tn = telnetlib.Telnet(host, int(port), timeout=5)
            tn.write(b"\r\n")
            prompt = _last_line(recv_prompt(tn, timeout=30, first_boot=True))
            if "(config" in prompt:
                prompt = _last_line(command(tn, "end"))
            if prompt.endswith(">"):
                prompt = _last_line(command(tn, "enable"))
            if not prompt.endswith("#") or "(config" in prompt:
                raise RuntimeError(f"Not at privileged EXEC: {prompt!r}")
            command(tn, "terminal length 0")
            return tn
        except (OSError, EOFError, TimeoutError, RuntimeError) as exc:
            last = exc
            if tn is not None:
                tn.close()
            time.sleep(3)
    raise RuntimeError(f"Unable to connect to IOS console {host}:{port}: {last}")


def node_console_host(node, compute_host):
    host = node.get("console_host")
    return compute_host if not host or host in {"0.0.0.0", "::", "127.0.0.1"} else host


def collect(host, node, commands):
    tn = console(host, node["console"])
    try:
        output = []
        for cmd in commands:
            output.append(f"\n==== {node['name']} :: {cmd} ====\n" + command(tn, cmd))
        return "\n".join(output)
    finally:
        tn.close()


def apply_to_router(host, node, name):
    tn = console(host, node["console"])
    try:
        # Save a local pre-change backup before altering each router. These can
        # contain secrets: evidence/ should stay private and out of Git.
        backup_dir = BASE / "evidence" / "prechange"
        backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = backup_dir / f"{stamp}_{name}_running.txt"
        backup.write_text(command(tn, "show running-config", timeout=50), encoding="utf-8")
        print(f"Saved pre-change router configuration: {backup}")
        # Config is additive; does not remove OSPF/LDP or edit the core interfaces.
        command(tn, "configure terminal")
        text = (BASE / "generated" / f"{name}.cfg").read_text(encoding="utf-8")
        for cmd in text.splitlines():
            if cmd.strip() and not cmd.strip().startswith("!"):
                command(tn, cmd)
        command(tn, "end")
        command(tn, "write memory", timeout=50)
    finally:
        tn.close()


def verify(nodes, compute_host):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence = BASE / "evidence"
    evidence.mkdir(exist_ok=True)
    evidence_path = evidence / f"{stamp}_phase3.txt"
    commands = {
        "PE1": ["show ip bgp vpnv4 all summary", "show ip bgp vpnv4 all", "show ip route vrf MUNI 10.11.10.0"],
        "PE2": ["show ip bgp vpnv4 all summary", "show ip bgp vpnv4 all", "show ip route vrf MUNI 10.10.10.0"],
        "P1": ["show ip route", "show mpls forwarding-table"],
        "CE-MUNI-HQ": ["show ip bgp summary", "show ip route 10.11.10.0"],
        "CE-MUNI-BR": ["show ip bgp summary", "show ip route 10.10.10.0"],
    }
    snippets = []
    for name, cmds in commands.items():
        node = nodes[name]
        print(f"Collecting {name} verification data...")
        snippets.append(collect(node_console_host(node, compute_host), node, cmds))
    pass_ping = True
    for name, dest, src in (("CE-MUNI-HQ", "10.11.10.1", "10.10.10.1"),
                            ("CE-MUNI-BR", "10.10.10.1", "10.11.10.1")):
        node = nodes[name]
        tn = console(node_console_host(node, compute_host), node["console"])
        try:
            result = command(tn, f"ping {dest} source {src}", timeout=30)
        finally:
            tn.close()
        success = "Success rate is 100 percent (5/5)" in result
        print(f"{'PASS' if success else 'FAIL'}: {name} ping {dest} source {src}")
        pass_ping &= success
        snippets.append(f"\n===== {name}: ping {dest} source {src} ({'PASS' if success else 'FAIL'}) =====\n{result}")
    evidence_path.write_text("\n\n".join(snippets), encoding="utf-8")
    print(f"Saved raw command evidence: {evidence_path}")
    print("Note: ping alone is not proof of MPLS VPN labels. Inspect VPNv4 labels, VRF routes and core LFIB as well.")
    return pass_ping


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--build", action="store_true", help="Create the two CEs and their links (no configs)")
    group.add_argument("--apply", action="store_true", help="Build and configure PEs/CEs; save snapshots")
    group.add_argument("--verify", action="store_true", help="Collect evidence and test CE connectivity only")
    ap.add_argument("--url", default="http://127.0.0.1:3080")
    ap.add_argument("--user", default="admin")
    args = ap.parse_args()
    if (args.apply or args.verify) and sys.version_info[:2] != (3, 12):
        raise RuntimeError("Console operations require Python 3.12 (telnetlib). Use py -3.12")
    inv = yaml.safe_load((BASE / "inventory.yaml").read_text(encoding="utf-8"))
    inv["project"] = os.environ.get("NORDNET_TARGET_PROJECT", "NORDNET-Core-POC")
    validate_inventory(inv)
    render(inv)
    if not (args.build or args.apply or args.verify):
        print("Render-only. Nothing changed in GNS3. Review generated/*.cfg, then --build / --apply.")
        return
    api = Controller(args.url, args.user, getpass("GNS3 local controller API password: "))
    version = api.call("GET", "/v2/version")
    print(f"Connected to GNS3 {version.get('version')}")
    base, compute_host = find_project(api, inv)
    nodes = build(api, base, inv, make_changes=not args.verify)
    print("Confirmed all five nodes and four links in the correct GNS3 project.")
    if args.build:
        print("Topology done. No IOS configurations changed. Inspect and run --apply when ready.")
        return
    if args.apply:
        # Start the known lab nodes, but never stop/reboot them.
        for name in ("PE1", "P1", "PE2", "CE-MUNI-HQ", "CE-MUNI-BR"):
            node = nodes[name]
            if node["status"] != "started":
                api.call("POST", f"{base}/nodes/{node['node_id']}/start", {})
                print(f"Started {name}")
        nodes = get_nodes(api, base)
        for name in DEPLOY:
            node = nodes[name]
            print(f"Applying additive VPN configuration to {name}...")
            apply_to_router(node_console_host(node, compute_host), node, name)
        print("All configurations applied/saved. Allow BGP convergence, then run --verify.")
    else:
        if any(n["status"] != "started" for n in nodes.values()):
            raise RuntimeError("All five routers must be started for --verify")
        ok = verify(nodes, compute_host)
        if not ok:
            raise RuntimeError("One or both CE-to-CE pings failed; inspect saved evidence and BGP routes")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, KeyError, requests.RequestException, KeyboardInterrupt) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
