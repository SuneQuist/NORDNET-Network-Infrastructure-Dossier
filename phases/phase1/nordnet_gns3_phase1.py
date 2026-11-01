#!/usr/bin/env python3
"""NORDNET Phase 1: safely create/reconcile a three-router GNS3 core.

Tested for syntax; requires a reachable GNS3 2.2 controller and an IOSv template.
Creates ONLY a project called NORDNET-Core-POC (or --project name).
Does not configure router IOS or remove any nodes/projects.
"""

from __future__ import annotations

import argparse
from getpass import getpass
import sys
from typing import Any

import requests
from requests.auth import HTTPBasicAuth

DEFAULT_TEMPLATE = "Cisco IOSv 15.9(3)M8"  # GNS3 template label; IOS image itself reports M3

NODES = {
    "PE1": (-320, 0),
    "P1": (0, 0),
    "PE2": (320, 0),
}
LINKS = [
    ("PE1", 0, "P1", 0),
    ("P1", 1, "PE2", 0),
]


class Gns3:
    def __init__(self, base_url: str, user: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(user, password)
        self.session.headers.update({"Accept": "application/json"})

    def api(self, method: str, path: str, payload: dict | None = None) -> Any:
        url = f"{self.base_url}{path}"
        try:
            response = self.session.request(method, url, json=payload, timeout=30)
            response.raise_for_status()
        except requests.RequestException as exc:
            if getattr(exc, "response", None) is not None:
                response = exc.response
                raise RuntimeError(
                    f"{method} {path}: HTTP {response.status_code}: "
                    f"{response.text[:700]}"
                ) from exc
            raise RuntimeError(f"{method} {path}: {exc}") from exc
        return response.json() if response.content else None


def iface(node: dict, index: int) -> dict:
    """Use the GNS3-reported port IDs, not guessed adapter/port coordinates."""
    ports = sorted(
        node.get("ports", []),
        key=lambda item: (item["adapter_number"], item["port_number"]),
    )
    if index >= len(ports):
        raise RuntimeError(f"{node['name']} exposes only {len(ports)} interfaces")
    port = ports[index]
    return {
        "node_id": node["node_id"],
        "adapter_number": port["adapter_number"],
        "port_number": port["port_number"],
    }


def endpoint_key(value: dict) -> tuple:
    return (value["node_id"], value["adapter_number"], value["port_number"])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:3080", help="GNS3 controller URL")
    parser.add_argument("--user", default="admin", help="GNS3 controller username")
    parser.add_argument("--compute", default="vm", help="Connected GNS3 VM compute ID")
    parser.add_argument("--template", default=DEFAULT_TEMPLATE, help="Exact IOSv template name")
    parser.add_argument("--project", default="NORDNET-Core-POC", help="Dedicated project name")
    parser.add_argument("--start", action="store_true", help="Start the three routers after creation")
    args = parser.parse_args()

    # No password printed, saved or passed as a shell argument.
    client = Gns3(args.url, args.user, getpass("GNS3 API password: "))
    version = client.api("GET", "/v2/version")
    print(f"Connected to GNS3 {version.get('version', 'unknown')}")

    computes = client.api("GET", "/v2/computes")
    compute = next((c for c in computes if c["compute_id"] == args.compute), None)
    if not compute or not compute.get("connected"):
        raise RuntimeError(f"Compute '{args.compute}' is not connected")
    if "qemu" not in compute.get("capabilities", {}).get("node_types", []):
        raise RuntimeError(f"Compute '{args.compute}' does not advertise QEMU support")

    templates = client.api("GET", "/v2/templates")
    matches = [t for t in templates if t.get("name") == args.template and t.get("template_type") == "qemu"]
    if len(matches) != 1:
        names = ", ".join(t.get("name", "?") for t in templates if t.get("template_type") == "qemu")
        raise RuntimeError(f"Expected one QEMU template '{args.template}', found {len(matches)}. Available: {names}")
    template = matches[0]
    if template.get("compute_id") not in (args.compute, None):
        raise RuntimeError(f"Template points to compute '{template.get('compute_id')}', not '{args.compute}'")
    if int(template.get("adapters", 0)) < 2:
        raise RuntimeError("IOSv template needs at least two adapters")

    projects = client.api("GET", "/v2/projects")
    matches = [p for p in projects if p.get("name") == args.project]
    if len(matches) > 1:
        raise RuntimeError("Multiple projects have this name; refusing to choose one")
    if matches:
        project = matches[0]
        print(f"Reusing project {project['name']} ({project['project_id']})")
    else:
        project = client.api("POST", "/v2/projects", {
            "name": args.project,
            "auto_start": False,
            "auto_close": False,
        })
        print(f"Created project {project['name']} ({project['project_id']})")

    pid = project["project_id"]
    base = f"/v2/projects/{pid}"
    if project.get("status") != "opened":
        client.api("POST", f"{base}/open", {})

    existing_nodes = {n["name"]: n for n in client.api("GET", f"{base}/nodes")}
    unexpected = set(existing_nodes) - set(NODES)
    if unexpected:
        raise RuntimeError(f"Project contains unexpected nodes {sorted(unexpected)}. Refusing to modify it.")

    nodes = {}
    for name, (x, y) in NODES.items():
        if name in existing_nodes:
            node = existing_nodes[name]
            if node.get("template_id") != template["template_id"] or node.get("compute_id") != args.compute:
                raise RuntimeError(f"Existing {name} uses another template/compute; refusing to replace it")
            print(f"Existing node {name}")
        else:
            node = client.api("POST", f"{base}/templates/{template['template_id']}", {
                "name": name, "compute_id": args.compute, "x": x, "y": y,
            })
            print(f"Created node {name} on compute '{node['compute_id']}'")
        nodes[name] = node

    existing_links = client.api("GET", f"{base}/links")
    used_ports = {
        endpoint_key(ep)
        for link in existing_links
        for ep in link.get("nodes", [])
    }
    existing_pairs = {
        frozenset(endpoint_key(ep) for ep in link.get("nodes", []))
        for link in existing_links
    }

    for aname, aport, bname, bport in LINKS:
        a = iface(nodes[aname], aport)
        b = iface(nodes[bname], bport)
        pair = frozenset((endpoint_key(a), endpoint_key(b)))
        if pair in existing_pairs:
            print(f"Existing link {aname}[{aport}] <-> {bname}[{bport}]")
            continue
        if endpoint_key(a) in used_ports or endpoint_key(b) in used_ports:
            raise RuntimeError(f"Port collision on {aname}[{aport}] <-> {bname}[{bport}]")
        client.api("POST", f"{base}/links", {"nodes": [a, b]})
        print(f"Created link {aname}[{aport}] <-> {bname}[{bport}]")
        used_ports.update((endpoint_key(a), endpoint_key(b)))

    if args.start:
        for name, node in nodes.items():
            if node["status"] != "started":
                client.api("POST", f"{base}/nodes/{node['node_id']}/start", {})
                print(f"Started {name}")

    print(f"\nDone. Open '{args.project}' in GNS3 GUI.")
    print("This phase creates topology only; IOS configurations are not yet deployed.")
    print("Expected wiring: PE1 Gi0/0 - P1 Gi0/0; P1 Gi0/1 - PE2 Gi0/0")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, KeyboardInterrupt) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
