#!/usr/bin/env python3
"""NORDNET isolated multi-interface lab service: DNS, HTTP and syslog.
Runs inside a GNS3 Docker node based on python:3.12-alpine. No pip packages.
The node is deliberately NOT an IP router. This is not a production firewall.
"""
import json
import http.client
import ipaddress
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SERVICE_IP = '10.10.30.250'
SERVICE_NAME = 'portal.nordnet.test'
ALLOWED = tuple(ipaddress.ip_network(net) for net in (
    '10.10.0.0/16', '10.11.0.0/16', '10.20.10.0/24', '10.30.10.0/24',
    '10.20.254.0/30', '10.30.254.0/30'))
RECORDS = {'portal.nordnet.test': SERVICE_IP,
           'dns.nordnet.test': SERVICE_IP,
           'logs.nordnet.test': SERVICE_IP}
DATA = Path('/data') if Path('/data').is_dir() else Path('/tmp')
LOCK = threading.Lock()
EVENTS = []


def allow(source):
    try: return any(ipaddress.ip_address(source) in net for net in ALLOWED)
    except ValueError: return False


def utc(): return datetime.now(timezone.utc).isoformat()


def configure_network():
    # GNS3 adds three Docker Ethernet adapters; run with root privileges.
    for iface, ip, mask in (
        ('eth0','10.10.30.250','255.255.255.0'),
        ('eth1','10.20.254.2','255.255.255.252'),
        ('eth2','10.30.254.2','255.255.255.252')):
        subprocess.run(['ifconfig',iface,ip,'netmask',mask,'up'], check=True)
    for args in (
        ['route','add','default','gw','10.10.30.1','eth0'],
        ['route','add','-net','10.20.10.0','netmask','255.255.255.0','gw','10.20.254.1','dev','eth1'],
        ['route','add','-net','10.30.10.0','netmask','255.255.255.0','gw','10.30.254.1','dev','eth2']):
        # Startup is normally fresh; harmless if a route already exists.
        result=subprocess.run(args, capture_output=True, text=True)
        if result.returncode and 'File exists' not in (result.stderr+result.stdout):
            raise RuntimeError('Cannot configure route: '+result.stderr.strip())
    forwarding=Path('/proc/sys/net/ipv4/ip_forward')
    if forwarding.read_text().strip() != '0':
        try: forwarding.write_text('0\n')
        except OSError as exc: raise RuntimeError('IPv4 forwarding enabled; refusing to run shared node') from exc
    if forwarding.read_text().strip() != '0':
        raise RuntimeError('IPv4 forwarding not disabled; refusing to run shared node')


def record_syslog(source, message):
    if not allow(source): return False
    item={'received_utc':utc(), 'source':source, 'message':message[:900]}
    with LOCK:
        EVENTS.append(item)
        if len(EVENTS)>200: del EVENTS[:-200]
        DATA.mkdir(parents=True, exist_ok=True)
        with (DATA/'nordnet_syslog.jsonl').open('a',encoding='utf-8') as f:
            f.write(json.dumps(item,ensure_ascii=True)+'\n')
    return True


class Syslog(socketserver.ThreadingUDPServer):
    allow_reuse_address=True

class SyslogHandler(socketserver.BaseRequestHandler):
    def handle(self):
        raw=self.request[0]
        record_syslog(self.client_address[0],raw.decode('utf-8',errors='replace'))


def decode_name(blob, offset=12):
    labels=[]
    for _ in range(60):
        if offset>=len(blob): raise ValueError('Truncated DNS name')
        n=blob[offset]; offset+=1
        if n==0: return '.'.join(labels).lower(),offset
        if n>63 or offset+n>len(blob): raise ValueError('Unsupported compressed or invalid DNS name')
        labels.append(blob[offset:offset+n].decode('ascii').lower()); offset+=n
    raise ValueError('DNS name too long')


def dns_response(query):
    if len(query)<12: return None
    tid, flags, qcount, _, _, _=struct.unpack('!6H',query[:12])
    if qcount!=1 or flags & 0x8000: return None
    try:
        name,end=decode_name(query)
        if end+4>len(query): return None
        qtype,qclass=struct.unpack('!HH',query[end:end+4])
    except (ValueError,UnicodeDecodeError): return None
    answer_ip=RECORDS.get(name) if qtype==1 and qclass==1 else None
    # QR+AA; no recursion. NXDOMAIN for unknown names, NOERROR with no answer for other types.
    rcode=3 if name not in RECORDS else 0
    resp=struct.pack('!6H',tid,0x8400|rcode,1,1 if answer_ip else 0,0,0)
    resp+=query[12:end+4]
    if answer_ip:
        resp+=b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+socket.inet_aton(answer_ip)
    return resp


class DNSUDP(socketserver.ThreadingUDPServer):
    allow_reuse_address=True

class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        if not allow(self.client_address[0]): return
        reply=dns_response(self.request[0])
        if reply: self.request[1].sendto(reply,self.client_address)


class DNSTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address=True

class DNSTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        if not allow(self.client_address[0]): return
        def recv_exact(n):
            data=b''
            while len(data)<n:
                chunk=self.request.recv(n-len(data))
                if not chunk: return None
                data+=chunk
            return data
        raw_len=recv_exact(2)
        if raw_len is None: return
        length=struct.unpack('!H',raw_len)[0]
        if length>4096: return
        payload=recv_exact(length)
        if payload is None: return
        response=dns_response(payload)
        if response: self.request.sendall(struct.pack('!H',len(response))+response)


class Web(BaseHTTPRequestHandler):
    def do_GET(self):
        if not allow(self.client_address[0]): self.send_error(403); return
        if self.path=='/health':
            payload={'status':'ok','service':'NORDNET local shared services','forwarding':'disabled','time':utc()}
        elif self.path=='/':
            payload={'message':'NORDNET simulated shared-services portal','dns':SERVICE_NAME,'scope':'local lab only'}
        elif self.path=='/events' and ipaddress.ip_address(self.client_address[0]) in ipaddress.ip_network('10.10.30.0/24'):
            with LOCK: payload={'recent_events':list(EVENTS)}
        else: self.send_error(404); return
        encoded=json.dumps(payload).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Cache-Control','no-store')
        self.send_header('Content-Length',str(len(encoded)))
        self.end_headers();self.wfile.write(encoded)
    def log_message(self,*args): pass


def serve(server):
    t=threading.Thread(target=server.serve_forever,daemon=True)
    t.start();return t


def selftest():
    # Verify the actual sockets, not just that threads started.
    query=(struct.pack('!6H',0x1234,0x0100,1,0,0,0)
           +b'\x06portal\x07nordnet\x04test\x00'+struct.pack('!HH',1,1))
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(query,(SERVICE_IP,53))
        response,_=sock.recvfrom(512)
        if response[:2]!=b'\x12\x34' or socket.inet_aton(SERVICE_IP) not in response:
            raise RuntimeError('DNS selftest failed')
    finally: sock.close()
    conn=http.client.HTTPConnection(SERVICE_IP,8080,timeout=4)
    try:
        conn.request('GET','/health')
        r=conn.getresponse()
        if r.status!=200 or b'\"status\": \"ok\"' not in r.read():
            raise RuntimeError('HTTP selftest failed')
    finally: conn.close()
    log=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    try: log.sendto(b'<14>NORDNET_SELFTEST', (SERVICE_IP,514))
    finally: log.close()
    deadline=time.monotonic()+4
    while time.monotonic()<deadline:
        with LOCK:
            if any('NORDNET_SELFTEST' in x['message'] for x in EVENTS): return True
        time.sleep(0.1)
    raise RuntimeError('Syslog selftest failed')


def main():
    configure_network()
    servers=[DNSUDP((SERVICE_IP,53),DNSHandler),
             DNSTCP((SERVICE_IP,53),DNSTCPHandler),
             Syslog((SERVICE_IP,514),SyslogHandler),
             ThreadingHTTPServer((SERVICE_IP,8080),Web)]
    for s in servers: serve(s)
    selftest()
    print('NORDNET_SERVICES_READY DNS=53/TCP+UDP HTTP=8080 SYSLOG=514/UDP ROUTING=OFF',flush=True)
    while True:
        print('NORDNET_SERVICES_HEALTH ready=1 forwarding=0 dns=ok http=ok syslog=ok',flush=True)
        time.sleep(8)

if __name__=='__main__': main()
