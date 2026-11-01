#!/usr/bin/env python3
"""NORDNET phase 2.2: render/optionally push IOSv OSPF+MPLS underlay.

Requires Python 3.12 to use the standard library telnetlib for GNS3 consoles.
Never creates/deletes nodes, links, projects or templates.
Default mode is OFFLINE RENDER ONLY; --apply explicitly enables live console changes.
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
from jinja2 import Environment, FileSystemLoader, StrictUndefined
import yaml

BASE = Path(__file__).resolve().parent
ROUTER_NAMES = ("PE1", "P1", "PE2")
SHOW_CMDS = (
    "show ip interface brief",
    "show ip ospf neighbor",
    "show ip route ospf",
    "show mpls interfaces",
    "show mpls ldp neighbor",
    "show mpls forwarding-table",
)
PROMPT = rb"[A-Za-z0-9_.-]+(?:\([^)\r\n]+\))?[>#]\s*$"
ERROR = re.compile(r"(?im)^\s*%\s*(Invalid input|Incomplete command|Ambiguous command|Error|Unrecognized command)")


def validate_design(design):
    if set(design["routers"]) != set(ROUTER_NAMES):
        raise ValueError("This stage requires precisely PE1, P1 and PE2")
    ips = set()
    for name, router in design["routers"].items():
        ipaddress.IPv4Address(router["loopback"])
        for ip in [router["loopback"]] + [it["ip"] for it in router["interfaces"]]:
            if ip in ips:
                raise ValueError(f"Duplicate IP: {ip}")
            ips.add(ip)
        for it in router["interfaces"]:
            ipaddress.IPv4Interface(f"{it['ip']}/{it['mask']}")
            if not re.fullmatch(r"GigabitEthernet0/[0-3]", it["name"]):
                raise ValueError(f"Unexpected interface {name} {it['name']}; review wiring")

def render(design):
    env = Environment(
        loader=FileSystemLoader(BASE / "templates"),
        undefined=StrictUndefined, trim_blocks=True, lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    template = env.get_template("iosv_underlay.j2")
    out = BASE / "generated"
    out.mkdir(exist_ok=True)
    for name, router in design["routers"].items():
        content = template.render(name=name, router=router,
                                  ospf_process=design["ospf_process"],
                                  ospf_area=design["ospf_area"])
        (out / f"{name}.cfg").write_text(content, encoding="utf-8")
        print(f"Rendered {out / (name + '.cfg')}")


class Api:
    def __init__(self, url, username, password):
        self.url = url.rstrip("/")
        self.s = requests.Session()
        self.s.auth = (username, password)
        self.s.headers.update({"Accept": "application/json"})

    def call(self, method, path, data=None):
        r = self.s.request(method, self.url + path, json=data, timeout=15)
        r.raise_for_status()
        return r.json() if r.content else None


def discover(api, design):
    projects = [x for x in api.call("GET", "/v2/projects") if x["name"] == design["project"]]
    if len(projects) != 1:
        raise RuntimeError(f"Expected exactly one {design['project']} GNS3 project, found {len(projects)}")
    pid = projects[0]["project_id"]
    base = f"/v2/projects/{pid}"
    if projects[0]["status"] != "opened":
        api.call("POST", base + "/open", {})
    nodes = {x["name"]: x for x in api.call("GET", base + "/nodes")}
    if set(nodes) != set(ROUTER_NAMES):
        raise RuntimeError(f"Expected {ROUTER_NAMES}, found {tuple(nodes)}. Refusing to configure an unexpected topology.")
    computes = {x["compute_id"]: x for x in api.call("GET", "/v2/computes")}
    for name, node in nodes.items():
        if node.get("node_type") != "qemu":
            raise RuntimeError(f"{name} is not a QEMU node")
        if node.get("compute_id") != "vm":
            raise RuntimeError(f"{name} is not on compute vm")
        if not computes.get("vm", {}).get("connected"):
            raise RuntimeError("GNS3 VM is disconnected")
        if node.get("console_type") != "telnet" or not node.get("console"):
            raise RuntimeError(f"{name} needs Telnet console; got {node.get('console_type')}")
    # Validate the linked ports before changing IOS configurations.
    id_to_name = {node["node_id"]: name for name, node in nodes.items()}
    port_links = set()
    for link in api.call("GET", base + "/links"):
        eps = link.get("nodes", [])
        if len(eps) != 2:
            raise RuntimeError("Unexpected multi-endpoint link")
        sides = []
        for ep in eps:
            if ep["node_id"] not in id_to_name:
                raise RuntimeError("Link includes unknown node")
            node = nodes[id_to_name[ep["node_id"]]]
            ports = [p for p in node["ports"] if
                     p["adapter_number"] == ep["adapter_number"] and
                     p["port_number"] == ep["port_number"]]
            if len(ports) != 1:
                raise RuntimeError("Port missing from GNS3 node metadata")
            sides.append((id_to_name[ep["node_id"]], ports[0]["name"]))
        port_links.add(frozenset(sides))
    expected = {
        frozenset({("PE1", "Gi0/0"), ("P1", "Gi0/0")}),
        frozenset({("P1", "Gi0/1"), ("PE2", "Gi0/0")}),
    }
    # Name could be GigabitEthernet0/0, rather than Gi0/0; normalise.
    def normal(x):
        return (x[0], x[1].replace("GigabitEthernet", "Gi"))
    port_links = {frozenset(normal(s) for s in p) for p in port_links}
    if port_links != expected:
        raise RuntimeError(f"GNS3 links do not match intended design: {port_links}")
    return base, nodes, computes["vm"]["host"]


def _last_console_line(raw):
    """Return the final visible nonempty console line from str/bytes/bytearray.

    recv_prompt() returns str, while the Telnet read buffer is a bytearray.
    Accept both so console reconnection/resume does not fail with AttributeError.
    """
    if isinstance(raw, str):
        text = raw
    elif isinstance(raw, (bytes, bytearray)):
        text = raw.decode("utf-8", errors="replace")
    else:
        raise TypeError(f"Unexpected console data type: {type(raw).__name__}")
    text = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", text)
    lines = text.replace("\r", "").split("\n")
    return next((line.strip() for line in reversed(lines) if line.strip()), "")


def recv_prompt(tn, timeout=15, handle_first_boot=False):
    """Read an IOS console until its *latest* line is a stable CLI prompt.

    IOS emits unsolicited %LINK/%LINEPROTO/%GRUB notifications after normal
    command prompts. telnetlib.expect() anchored at end-of-buffer can then
    time out forever because the latest line is a notification, not a prompt.
    After quiet output, send an empty line to request a *fresh* IOS prompt.
    """
    prompt = re.compile(r"^[A-Za-z0-9_.-]+(?:\([^()\n]+\))?[>#]$")
    wizard = re.compile(r"Would you like to enter the initial configuration dialog\?\s*\[yes/no\]:?\s*$", re.I)
    press_enter = re.compile(r"Press (?:RETURN|ENTER) to get started!?", re.I)
    deadline = time.monotonic() + timeout
    last_rx = time.monotonic()
    last_nudge = last_rx
    last_action = None
    nudges = 0
    dialogue_answers = 0
    result = bytearray()
    while time.monotonic() < deadline:
        try:
            chunk = tn.read_very_eager()
        except EOFError as exc:
            raise RuntimeError("IOS console disconnected") from exc
        now = time.monotonic()
        if chunk:
            result.extend(chunk)
            last_rx = now
            if len(result) > 2_000_000:
                raise RuntimeError("Excessive IOS console output (>2 MB); check for message flooding")
        tail = _last_console_line(result)
        quiet_for = now - last_rx
        # Only respond to the exact initial IOS setup question; never answer
        # other confirmations or credentials automatically.
        if wizard.search(tail):
            if not handle_first_boot:
                raise RuntimeError("Unexpected IOS initial setup dialog")
            if last_action != ("no", tail):
                tn.write(b"no\r\n")
                print("  Answered IOS first-boot configuration dialog: no")
                dialogue_answers += 1
                last_action = ("no", tail)
                if dialogue_answers > 5:
                    raise RuntimeError("Repeated IOS initial setup dialog")
        elif press_enter.search(tail):
            if not handle_first_boot:
                raise RuntimeError("Unexpected IOS first-boot prompt")
            if last_action != ("enter", tail):
                tn.write(b"\r\n")
                last_action = ("enter", tail)
        elif tail.lower().endswith("password:"):
            raise RuntimeError("Unexpected console password prompt; refusing automatic login")
        elif re.search(r"\[yes/no\]:?$", tail, re.I):
            raise RuntimeError("Unexpected IOS yes/no question; refusing automatic confirmation")
        elif prompt.fullmatch(tail):
            # A short settle period catches the common case where an IOS log
            # message is printed *after* an apparent prompt.
            if quiet_for >= 0.30:
                return result.decode("utf-8", errors="replace")
        elif quiet_for >= 0.8 and now - last_nudge >= 0.8:
            # The last line is unsolicited syslog (or output from an in-flight
            # command). Ask IOS to reprint its prompt before continuing.
            tn.write(b"\r\n")
            last_nudge = now
            nudges += 1
            if nudges >= 8:
                break
        time.sleep(0.06)
    text = result.decode("utf-8", errors="replace")
    raise RuntimeError(
        f"IOS prompt not recovered within {timeout}s; final console output: {text[-500:]!r}"
    )


def line(tn, text, timeout=15):
    tn.write(text.encode("ascii") + b"\r\n")
    result = recv_prompt(tn, timeout)
    if ERROR.search(result):
        raise RuntimeError(f"IOS rejected {text!r}: {result[-500:]}")
    return result


def connect_console(host, port):
    # telnetlib exists on Python 3.12 but emits a deprecation warning.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        import telnetlib
    deadline = time.monotonic() + 150
    last = None
    while time.monotonic() < deadline:
        tn = None
        try:
            tn = telnetlib.Telnet(host, int(port), timeout=5)
            tn.write(b"\r\n")
            received = recv_prompt(tn, timeout=25, handle_first_boot=True)
            prompt = _last_console_line(received)
            # A previous failed deployment may have left the router in
            # configuration mode. Restore privileged EXEC safely before
            # issuing terminal length 0 or deploying a second time.
            if "(config" in prompt:
                received = line(tn, "end")
                prompt = _last_console_line(received)
            if prompt.endswith(">"):
                received = line(tn, "enable")
                prompt = _last_console_line(received)
            if not prompt.endswith("#") or "(config" in prompt:
                raise RuntimeError(f"Expected privileged EXEC prompt; got {prompt!r}")
            return tn
        except (OSError, EOFError, TimeoutError, RuntimeError) as exc:
            last = exc
            if tn is not None:
                tn.close()
            time.sleep(4)
    raise RuntimeError(f"Could not open ready IOS console at {host}:{port}: {last}")


def configure_and_collect(host, port, name):
    tn = connect_console(host, port)
    try:
        line(tn, "terminal length 0")
        line(tn, "configure terminal")
        content = (BASE / "generated" / f"{name}.cfg").read_text(encoding="utf-8")
        for cmd in content.splitlines():
            if cmd.strip() and not cmd.lstrip().startswith("!"):
                line(tn, cmd, timeout=20)
        line(tn, "end")
        line(tn, "write memory", timeout=30)
        outputs = []
        for cmd in SHOW_CMDS:
            outputs.append(f"\n===== {name}: {cmd} =====\n" + line(tn, cmd, timeout=25))
        return "".join(outputs)
    finally:
        tn.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Explicitly send configurations via the nodes' Telnet consoles")
    parser.add_argument("--url", default="http://127.0.0.1:3080")
    parser.add_argument("--user", default="admin")
    args = parser.parse_args()
    if args.apply and sys.version_info[:2] != (3, 12):
        raise RuntimeError("The --apply console adapter requires Python 3.12. Run: py -3.12 nordnet_phase2.py --apply")
    design = yaml.safe_load((BASE / "topology.yaml").read_text(encoding="utf-8"))
    design["project"] = os.environ.get("NORDNET_TARGET_PROJECT", "NORDNET-Core-POC")
    validate_design(design)
    render(design)
    if not args.apply:
        print("\nRender-only complete. Review files in generated/. No device configurations changed.")
        print("To push configurations: py -3.12 nordnet_phase2.py --apply")
        return
    api = Api(args.url, args.user, getpass("GNS3 local controller API password: "))
    base, nodes, host = discover(api, design)
    print("Validated project, Cisco nodes, interface links and GNS3 VM connectivity.")
    print(f"Router configurations will now be pushed to the existing consoles in {design['project']}.")
    for name in ROUTER_NAMES:
        if nodes[name]["status"] != "started":
            api.call("POST", f"{base}/nodes/{nodes[name]['node_id']}/start", {})
            print(f"Started {name}")
    evidence_dir = BASE / "evidence"
    evidence_dir.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for name in ROUTER_NAMES:
        node = nodes[name]
        console_host = node.get("console_host")
        if not console_host or console_host in ("0.0.0.0", "::", "127.0.0.1"):
            console_host = host
        print(f"Applying {name} via Telnet console {console_host}:{node['console']} ...")
        output = configure_and_collect(console_host, node["console"], name)
        file = evidence_dir / f"{stamp}_{name}_initial.txt"
        file.write_text(output, encoding="utf-8")
        print(f"Saved command evidence: {file}")
    print("\nConfiguration applied and snapshots collected.")
    print("Allow OSPF/LDP to converge, then check neighbours in GNS3 consoles:")
    for cmd in ("show ip ospf neighbor", "show mpls ldp neighbor", "show mpls forwarding-table"):
        print("  " + cmd)
    print("On PE1, verify: ping 172.20.255.2 source Loopback0")
    print("Note: these snapshots do NOT automatically certify test success.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, requests.RequestException, KeyboardInterrupt) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
