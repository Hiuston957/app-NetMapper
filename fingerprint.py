"""Passive, bounded identification from HTTP metadata and SSH/FTP/SMTP banners."""
import http.client
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor

HTTP_PORTS={80:'http',81:'http',443:'https',5000:'http',5001:'https',8006:'https',8080:'http',8081:'http',8443:'https',8843:'https',8880:'http',8881:'http',8882:'http',8888:'http',9000:'http',9090:'https',9443:'https',8043:'https',8088:'http',7443:'https',5005:'http',5006:'https',5988:'http',5989:'https',631:'http',3000:'http',10000:'https'}
SIGNATURES=[
 ('Dahua',r'dahua|dh[- ]?ipc|dhi[- ]?nvr|web service.*dahua'),
 ('Hikvision',r'hikvision|hik-connect|webcomponents|hik[- ]?connect'),
 ('Synology',r'synology|diskstation|synology diskstation|dsm login'),
 ('QNAP',r'qnap|qts login|qnap turbo'),
 ('Proxmox',r'proxmox virtual environment|pve manager|proxmox'),
 ('Ubiquiti',r'ubiquiti|unifi network|unifi os|unifi protect'),
 ('MikroTik',r'mikrotik|routeros|webfig'),
 ('Fortinet',r'fortigate|fortinet|fortios'),
 ('Palo Alto Networks',r'palo alto networks|pan-os|globalprotect'),
 ('Dell',r'idrac|integrated dell remote access|dell remote access'),
 ('HPE',r'hewlett packard enterprise|hpe ilo|integrated lights-out|ilo 5'),
 ('TP-Link',r'tp-link|omada controller|omada cloud'),
 ('Mercusys',r'mercusys|ac12g'),
 ('Axis',r'axis communications|axis camera|axis network'),
 ('Brother',r'brother industries|brother web based management'),
 ('HP',r'hp laserjet|hp embedded web server|hewlett-packard'),
 ('Cisco',r'cisco systems|cisco ios|cisco meraki'),
 ('Zyxel',r'zyxel|zywall|nebula cloud'),
 ('TrueNAS',r'truenas|freenas'),
 ('VMware',r'vmware esxi|vmware host client|vsphere client'),
]

def http_probe(ip, port, scheme):
    conn=None
    try:
        cls=http.client.HTTPSConnection if scheme=='https' else http.client.HTTPConnection
        opts={'timeout':1.3}
        if scheme=='https':opts['context']=ssl._create_unverified_context() # read-only discovery of internal self-signed panels
        conn=cls(ip,port,**opts)
        conn.request('GET','/',headers={'User-Agent':'NetMapper/7.0','Connection':'close','Accept':'text/html'})
        res=conn.getresponse()
        headers=dict((k.lower(),v[:250]) for k,v in res.getheaders() if k.lower() in ('server','www-authenticate','location','x-powered-by'))
        body=res.read(12000).decode('utf-8','replace')
        title=re.search(r'<title[^>]*>(.*?)</title>',body,re.I|re.S)
        title=re.sub(r'\s+',' ',title.group(1)).strip()[:160] if title else ''
        return {'port':port,'scheme':scheme,'status':res.status,'title':title,'headers':headers,'sample':re.sub(r'<[^>]+>',' ',body)[:12000], 'html':body[:12000]}
    except (OSError,ssl.SSLError,http.client.HTTPException,ValueError):return None
    finally:
        if conn:conn.close()

def banner_probe(ip,port):
    if port not in (21,22,25,110,143):return None
    try:
        with socket.create_connection((ip,port),timeout=1) as s:
            s.settimeout(0.9)
            b=s.recv(350).decode('utf-8','replace').strip()
            return {'port':port,'banner':re.sub(r'[\x00-\x1f]',' ',b)[:250]} if b else None
    except (OSError,ValueError):return None

def identify(ip,ports):
    checks=[(p['port'],p.get('web_scheme') or HTTP_PORTS.get(p['port'])) for p in ports if p.get('web_scheme') or p['port'] in HTTP_PORTS]
    with ThreadPoolExecutor(max_workers=8) as pool:
        http=list(filter(None,pool.map(lambda x:http_probe(ip,*x),checks)))
        banners=list(filter(None,pool.map(lambda p:banner_probe(ip,p['port']),ports)))
    evidence=' '.join(' '.join([x['title'],*x['headers'].values(),x['sample']]) for x in http)
    hits=[]
    for name,regex in SIGNATURES:
        if re.search(regex,evidence,re.I):hits.append({'vendor':name,'method':'HTTP/HTTPS','confidence':'wysoka','evidence':next((x['title'] or x['headers'].get('server','') or 'Treść HTTP') for x in http if re.search(regex,' '.join([x['title'],*x['headers'].values(),x['sample']]),re.I))[:120]})
    # A banner may support classification only if it explicitly names a vendor.
    for x in banners:
        for name,regex in SIGNATURES:
            if re.search(regex,x['banner'],re.I) and name not in [h['vendor'] for h in hits]:hits.append({'vendor':name,'method':'baner TCP','confidence':'wysoka','evidence':x['banner'][:120]})
    return {'http':[{k:v for k,v in x.items() if k!='sample'} for x in http], 'banners':banners,'matches':hits}
