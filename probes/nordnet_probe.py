"""Run as the foreground process in three lab-only GNS3 Docker probe nodes.

The probe configures only its own container. It does not route traffic.
Its periodic single-line JSON records are consumed over the node's GNS3 console.
"""
from __future__ import annotations
from datetime import datetime, timezone
from http.client import HTTPConnection
from urllib.error import HTTPError
import ipaddress
import json
import os
import socket
import struct
import subprocess
import time

SERVICE = '10.10.30.250'
SERVICE_PORT = 8080
PROFILE = {
    'PROBE-MUNI': ('10.10.30.251', '10.10.30.1', False),
    'PROBE-UNIV': ('10.20.10.20', '10.20.10.1', True),
    'PROBE-HEALTH': ('10.30.10.20', '10.30.10.1', True),
}

def utc():
    return datetime.now(timezone.utc).isoformat()

def configure(node):
    ip, gateway, _ = PROFILE[node]
    subprocess.run(['ifconfig', 'eth0', ip, 'netmask', '255.255.255.0', 'up'], check=True)
    r = subprocess.run(['route', 'add', 'default', 'gw', gateway, 'eth0'], capture_output=True, text=True)
    if r.returncode and 'File exists' not in (r.stdout + r.stderr):
        raise RuntimeError('Default route failed: '+r.stderr[:150])
    # These probes MUST NOT become customer-network transit devices.
    forward = '/proc/sys/net/ipv4/ip_forward'
    with open(forward, encoding='ascii') as f:
        enabled = f.read().strip() != '0'
    if enabled:
        # Match the existing NORDNET shared-services container: disable in
        # this container's network namespace, then verify fail-closed.
        try:
            with open(forward, 'w', encoding='ascii') as f:
                f.write('0\n')
        except OSError as exc:
            raise RuntimeError('Cannot disable IPv4 forwarding in probe') from exc
    with open(forward, encoding='ascii') as f:
        if f.read().strip() != '0':
            raise RuntimeError('IPv4 forwarding still enabled; refusing to run')

def qname(text):
    return b''.join(bytes([len(x)]) + x.encode('ascii') for x in text.split('.')) + b'\x00'

def check_dns():
    tid = 0x6437
    query = struct.pack('!6H', tid, 0x0100, 1, 0, 0, 0) + qname('portal.nordnet.test') + struct.pack('!HH', 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(query, (SERVICE, 53))
        data, origin = s.recvfrom(1024)
    finally:
        s.close()
    if origin[0] != SERVICE or len(data) < len(query) + 16:
        raise RuntimeError('DNS reply missing/invalid source')
    got, flags, _, answers, _, _ = struct.unpack('!6H', data[:12])
    if got != tid or not (flags & 0x8000) or flags & 0xF or answers < 1:
        raise RuntimeError('Unexpected DNS response header')
    if socket.inet_aton(SERVICE) not in data[12+len(query)-12:]:
        raise RuntimeError('DNS answer does not include service A record')
    return True

def request(path):
    con = HTTPConnection(SERVICE, SERVICE_PORT, timeout=4)
    try:
        con.request('GET', path, headers={'Host': 'portal.nordnet.test'})
        reply = con.getresponse()
        body = reply.read(1000000)
        return reply.status, body
    finally:
        con.close()

def send_syslog(node):
    payload = '<134>NORDNET_ACCEPTANCE:'+node
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.sendto(payload.encode('ascii'), (SERVICE, 514))
    finally:
        s.close()

def measure(node):
    ip, _, restricted = PROFILE[node]
    item = {'node': node, 'source_ip': ip, 'created_utc': utc(), 'dns_ok': False,
            'http_ok': False, 'events_policy_ok': False, 'syslog_sent': False,
            'syslog_observed': None, 'errors': []}
    try: item['dns_ok'] = check_dns()
    except Exception as e: item['errors'].append('dns: '+str(e)[:180])
    try:
        code, body = request('/health')
        doc = json.loads(body)
        item['http_ok'] = code == 200 and doc.get('status') == 'ok' and doc.get('forwarding') == 'disabled'
        if not item['http_ok']: item['errors'].append('HTTP health/status mismatch')
    except Exception as e: item['errors'].append('http: '+str(e)[:180])
    try:
        code, body = request('/events')
        if restricted:
            item['events_policy_ok'] = code in (403, 404)
        else:
            doc = json.loads(body)
            item['events_policy_ok'] = code == 200 and isinstance(doc.get('recent_events'), list)
            if item['events_policy_ok']:
                # Fresh syslog messages from all probes are independently validated
                # by the municipal probe via /events, not by the sender itself.
                item['events'] = [
                    {'source': e.get('source'), 'message': e.get('message'), 'received_utc': e.get('received_utc')}
                    for e in doc['recent_events'] if 'NORDNET_ACCEPTANCE:' in str(e.get('message',''))
                ][-60:]
        if not item['events_policy_ok']: item['errors'].append('HTTP /events policy mismatch')
    except Exception as e: item['errors'].append('events: '+str(e)[:180])
    try:
        send_syslog(node)
        item['syslog_sent'] = True  # UDP send is not proof the collector received it.
    except Exception as e: item['errors'].append('syslog send: '+str(e)[:180])
    return item

def main():
    name = os.environ.get('NORDNET_PROBE_NAME', '')
    # The image launch command embeds an explicit argument rather than relying
    # on hostname or environment injection by GNS3.
    import sys
    if len(sys.argv) == 2:
        name = sys.argv[1]
    if name not in PROFILE: raise RuntimeError('Unknown probe identity')
    configure(name)
    print('NORDNET_PROBE_READY '+name, flush=True)
    while True:
        print('NORDNET_E2E_V1 '+json.dumps(measure(name), separators=(',',':')), flush=True)
        time.sleep(12)

if __name__ == '__main__': main()
