# NORDNET v0.9.1 — Full LOCAL Implementation Bundle (Named Projects)

**Status:** One-command *orchestrator* built and tested offline. **Fresh Phase 1→v0.8 end-to-end GNS3 deployment has NOT been exercised on a live controller**; do not claim production-ready provisioning. The separate phases have been used successfully across the NORDNET project, but their end-to-end combination still needs a trial on an isolated controller.

This ZIP is a consolidation of the real Phase 1–6.1 scripts, corrected v0.7.2 enterprise deployment, v0.8.6 acceptance scripts, v0.8.5 probe repair and v0.8.7-equivalent test fix. It is **not** a complete off-site SOC, IPsec VPN, management-plane AAA or dedicated OOB network.

## What is included

- Phase 1: project creation and initial PE1–P1–PE2 topology.
- Phase 2: OSPF, LDP, loopbacks and underlay.
- Phase 3: MUNI VRF, MP-BGP VPNv4 and two CE routers.
- Phase 4: P2 as the higher-cost backup provider path.
- Phase 5: independent UNIV and HEALTH VRFs, with CE/PE eBGP.
- Phase 6.1: HQ/branch IOSvL2 switches, real VLAN trunks, seven static VPCS clients, branch/HQ connectivity and customer isolation.
- v0.7.2: 1 Python Alpine shared-service Docker node (DNS/HTTP/syslog), two DHCP VPCS, four CE DHCP pools, private UNIV/HEALTH host-only service attachments and evidence.
- v0.8.6: optional **temporary acceptance fixture** (3 Docker probes and 2 inline switches), read-only active E2E verification, VPCS startup script audit, restore command and management-hardening review.
- `nordnet.py`: a guarded one-command orchestrator and log writer.
- `prefix_helper.py`: CIDR calculator, prefix-overlap audit, route summarization and review-only Cisco prefix-list generator.
- `tests/`: offline mock and regression tests. No Cisco images included.

Expected **normal** topology: **20 nodes / 22 links**. Optional acceptance fixture: **25 nodes / 27 links**. The 25-node fixture is **not** the normal architecture.

## Preconditions

1. Windows with Python **3.12**, GNS3 controller reachable at `http://127.0.0.1:3080` using Basic Auth `admin` (prompted password), connected compute ID `vm` (the VM IP is discovered, not hardcoded).
2. Licensed installed QEMU templates with exact names `Cisco IOSv 15.9(3)M8` and `Cisco IOSvL2 15.2.1`, and the Docker image `python:3.12-alpine` **inside the GNS3 VM**. Never expose the GNS3 API/Telnet consoles to the Internet.
3. GNS3 VM capable of running 10 IOSv/IOSvL2 routers/switches, 9 VPCS and a service container; available RAM/storage checked by operator.
4. Export your project and preserve `evidence/` before any maintenance. GNS3 project export may require **all nodes stopped**; restore the project to running state and allow BGP/OSPF/DHCP recovery before validation. Docker volumes may need separate backup.
5. **Fresh mode refuses any existing GNS3 project named `NORDNET-Core-POC`**. It does not overwrite, clear, or reset the project that has been validated already. Use a separate controller/environment for fresh-build trials.

## Setup (PowerShell)

Extract ZIP into `Downloads\NORDNET_Full_Local_Bundle_v091` and run once:

```powershell
cd "$env:USERPROFILE\Downloads\NORDNET_Full_Local_Bundle_v091"
py -3.12 -m pip install -r .\requirements.txt
py -3.12 -m unittest discover -s tests -v
```

**Offline plan / review:**

```powershell
py -3.12 .\nordnet.py plan --mode fresh --name "NORDNET-Test-01"
```

**Read-only live preflight of a new *project name* (the controller may contain other projects):**

```powershell
py -3.12 .\nordnet.py preflight --mode fresh --name "NORDNET-Test-01"
```

**One command: FULL LOCAL deployment into a newly created GNS3 project under the name you choose:**

```powershell
py -3.12 .\nordnet.py deploy --mode fresh --name "NORDNET-Test-01" --approve-maintenance --backup-confirmed
```

The command prompts for the API password only once, then runs the historical deployment scripts sequentially with verification gates. It automatically writes recognized DHCP startup scripts, requests missing DHCP leases on the two VPCS and performs final enterprise verification. It does not reboot all nodes, pull Docker images or deploy external connectivity. **If a stage fails, it stops and leaves evidence; it does not blindly replay the failed configuration or claim rollback.** Use the stage evidence and restore your backup when required; no automatic resumption of partly configured projects is offered.

### Use with the EXISTING working NORDNET project

The current validated lab has either a **20-node normal topology** or a **25-node temporary acceptance fixture**. To avoid damaging it:

```powershell
# NO configuration changes (works only for normal 20-node topology)
py -3.12 .\nordnet.py validate --mode existing
# Named project: py -3.12 .\nordnet.py validate --mode existing --name "NORDNET-Test-01"
```

If it still contains **25 nodes**, the orchestrator deliberately refuses; restore your test fixture using the existing, already validated `nordnet_acceptance.py --restore --approve-maintenance` from the active project folder *after securing the evidence and backup*. Then verify the normal topology with `nordnet_enterprise.py --verify`.

If there are exactly **17 original Phase 6.1 nodes**, the following single command can deploy the local enterprise/DHCP service add-on with an approved backup:

```powershell
py -3.12 .\nordnet.py deploy --mode existing --approve-maintenance --backup-confirmed
```

For an **already existing 20-node lab**, that same deployment command skips Cisco reconfiguration and only reconciles DHCP startup/leases then verifies. It does not re-run Phase 1–6.1. Unknown or partially modified layouts are rejected.

**DHCP-only VPCS renewal** after a complete cold start (does not touch IOS/Cisco devices and does not save static leases):

```powershell
py -3.12 .\nordnet.py recover-dhcp --approve-maintenance --backup-confirmed
```

### Optional active application acceptance on the verified normal topology

After deployment: the normal enterprise `--verify` checks architecture and service readiness. The full 3-site DNS/HTTP/syslog E2E acceptance needs its **temporary fixture**, which is an independent maintenance activity:

```powershell
# First discover the actual project UUID from the GNS3 UI/API; then:
py -3.12 .\nordnet_acceptance.py --plan
py -3.12 .\nordnet_acceptance.py --prepare --project-id PROJECT_UUID --approve-maintenance
# Check temporary switch Gi1/2 in VLAN 30 on SW-MUNI-HQ (see Operations docs).
py -3.12 .\nordnet_acceptance.py --verify --project-id PROJECT_UUID
# Only after PASS and backup, restore temporary topology:
py -3.12 .\nordnet_acceptance.py --restore --project-id PROJECT_UUID --approve-maintenance
py -3.12 .\nordnet_enterprise.py --verify
```

**Do NOT run `--prepare` twice.** The temporary municipal `SW-MUNI-HQ Gi1/2` access VLAN 30 can require an explicit setup before E2E testing and cleanup after fixture restoration. The wrapper does not claim to fully automate this temporary physical-interface step.

### Prefix helper — offline only

```powershell
py -3.12 .\nordnet.py prefix inventory
py -3.12 .\nordnet.py prefix explain 10.10.30.0/24
py -3.12 .\nordnet.py prefix check
py -3.12 .\nordnet.py prefix contains 10.10.30.0/24 10.10.30.250
py -3.12 .\nordnet.py prefix summarize 10.10.10.0/24 10.10.11.0/24
py -3.12 .\nordnet.py prefix prefix-list MUNI-OUT 10.10.10.0/24 10.10.20.0/24
```

`prefix-list` prints **review-only** commands; it does not apply router configuration. Subnet masks and IOS wildcards are shown by `explain`. The `check` test detects IP-prefix overlap in documented subnets, not all routing or security-policy conflicts. Config templates enforce the original fixed prefix plan, so changing subnets in the helper doesn't change the infrastructure.

## What a PASS means

- Local MPLS routing, VRF customer segmentation, and enterprise service readiness as checked by the existing scripts.
- Successful DHCP leases and startup scripts on the two additional VPCS.
- Timestamped verification/evidence files under `evidence/`.

**It does NOT yet mean:** automatic whole-project recovery with no intervention; validated off-site IPsec/VPN/SOC; authenticated SSH/AAA; production-grade firewall inspection; or a formally verified SLA. Previous local security audit found 22 management-plane findings. Preserve these as engineering backlog.

## Troubleshooting and safety

- Do not run the legacy `nordnet_local.py --apply` against a complete 20-node enterprise project or the acceptance fixture.
- `--mode fresh --name NEW_NAME` creates only a project of that name and refuses any existing project with the same name. Never point it at the validated main project.
- Directly invoking the legacy phase scripts still defaults to `NORDNET-Core-POC`; the `nordnet.py` orchestrator propagates the requested name to every deployment phase.
- For direct acceptance tests on a newly named project, explicitly supply its own GNS3 UUID with `nordnet_acceptance.py --project-id UUID`; the acceptance script has a legacy default UUID.
- Running two full 20-node labs simultaneously on a 32 GB system can exhaust resources. Stop the original nodes (do not delete them) before starting a fresh deployment.
- If the GNS3 VM IP changes, the scripts discover the current host through `/v2/computes`.
- If Docker image is missing: open the GNS3 VM console and run `docker pull python:3.12-alpine`, then retry preflight; no automatic network download.
- If a verification fails soon after startup, allow routing to converge. The orchestrator retries **read-only tests** only. It does not re-run configuration stages automatically.
- Cold-start DHCP may initially be `0.0.0.0`; use `recover-dhcp` after routing convergence.
- Service data in `/data` is stored in a Docker volume and may not be included in a standard project export.
- Project and console evidence may contain secrets; do not upload them to public repositories without redaction.

## Validation and provenance

This release consolidates the previously developed NORDNET code. Its new orchestration and prefix helpers have **offline unit tests**. A **new, blank-project, one-command live build has not been run**, so treat the first fresh execution as a controlled lab trial with snapshot/export and operator observation. A prior version of NORDNET successfully passed v0.8 active acceptance locally, but that success does not prove this new orchestrator's entire fresh path.

## v0.9.1 project-name change

The `--name` parameter is supported on `plan`, `preflight`, `deploy`, `validate` and `recover-dhcp`. For a fresh build the preflight inspects **only the requested name**. Phase 1 creates that GNS3 project and the remaining phases select it by name; no existing `NORDNET-Core-POC` project is needed. Existing named projects are never overwritten by fresh mode. The selected project name is kept in a scoped process environment variable while the legacy phase scripts run and is restored after the operation. The addressing inside the network is unchanged. The full named-project workflow has unit and mock-controller tests, but its complete live deployment remains untested.
# NORDNET---Network-Infrastructure-Dossier
