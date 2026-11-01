# NORDNET v0.9.1 – quickstart (navngivne projekter)

Bundlen kan oprette et nyt GNS3-projekt med et valgfrit navn via **`--name`**. Den kræver ikke, at `NORDNET-Core-POC` eksisterer, og den blokkerer ikke, fordi det oprindelige projekt ligger på samme controller. **Den nægter derimod at overskrive et projekt med samme navn som det ønskede nye projekt.**

Implementeringen omfatter den lokale NORDNET v0.8-arkitektur: MPLS L3VPN, MUNI/UNIV/HEALTH VRF'er, redundans, VLAN, VPCS, DHCP, DNS, HTTP, syslog og test/evidence. Eksternt SOC/IPsec og AAA-hardening er ikke implementeret.

## Installation (Windows PowerShell)

```powershell
cd "$env:USERPROFILE\Downloads\NORDNET_Full_Local_Bundle_v091"
py -3.12 -m pip install -r .\requirements.txt
py -3.12 -m unittest discover -s tests -v
```

## Nyt projekt fra nul – også på en controller, der allerede indeholder NORDNET-Core-POC

Vælg et **helt nyt navn**:

```powershell
py -3.12 .\nordnet.py plan --mode fresh --name "NORDNET-Test-01"
py -3.12 .\nordnet.py preflight --mode fresh --name "NORDNET-Test-01"

# Opretter projektet, noderne og links og kører deployment af de lokale tjenester:
py -3.12 .\nordnet.py deploy --mode fresh --name "NORDNET-Test-01" --approve-maintenance --backup-confirmed
```

API-password tastes kun ved prompt og gemmes ikke. GNS3 VM (`compute_id=vm`), licenserede IOSv/IOSvL2-templates og Docker-imaget `python:3.12-alpine` skal være tilgængelige. Der kræves ingen forudgående NORDNET-topologi. Alle ældre fasescripts får det valgte navn via en midlertidig intern projektkontekst.

**Vigtigt:** Den komplette one-command-deployment er **offline-testet, men endnu ikke live-valideret fra et tomt projekt**. Den kan derfor stoppe midtvejs; den laver hverken automatisk rollback eller blind genkørsel af konfiguration. Brug et testprojekt og bevar backups/evidence. Ved 32 GB RAM kan to fuldt startede NORDNET-projekter blive for ressourcekrævende; stop noderne i det oprindelige projekt uden at slette projektet, inden det nye sættes i drift.

## Eksisterende projekt

```powershell
# Standardnavnet bruges, når --name udelades
py -3.12 .\nordnet.py validate --mode existing

# Et andet navngivet 20-node-projekt
py -3.12 .\nordnet.py validate --mode existing --name "NORDNET-Test-01"

# DHCP-renew efter cold start på et valgt eksisterende projekt
py -3.12 .\nordnet.py recover-dhcp --mode existing --name "NORDNET-Test-01" --approve-maintenance --backup-confirmed
```

Et projekt med 25 midlertidige acceptance-testnoder skal gendannes med den eksisterende, projekt-id-specifikke acceptance-procedure først. Hvis du bruger `nordnet_acceptance.py` direkte på et nyt projekt, skal du eksplicit angive det nye **`--project-id`**, ikke UUID'et for det oprindelige projekt. Ved direkte brug af de gamle fasefiler er deres standardprojektnavn fortsat `NORDNET-Core-POC`; brug normalt orchestratoren.

## Prefix-helper (offline)

```powershell
py -3.12 .\nordnet.py prefix inventory
py -3.12 .\nordnet.py prefix explain 10.10.30.0/24
py -3.12 .\nordnet.py prefix check
py -3.12 .\nordnet.py prefix prefix-list MUNI-OUT 10.10.10.0/24 10.11.10.0/24
```

Prefix-list-kommandoer bliver **kun vist**, ikke anvendt på routerne.
