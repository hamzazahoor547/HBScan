#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║         HBScan v2.1 - HawkByte Network Scanner       ║
║         Educational Use Only - Scan Legal Targets    ║
╚══════════════════════════════════════════════════════╝
"""

import socket
import threading
import sys
import time
import os
import json
import ssl
import subprocess
import ipaddress
import datetime
import urllib.request
import http.client
import concurrent.futures

# ─────────────────────────────────────────
#  COLORS
# ─────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

# ─────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────
VERSION      = "2.1.0"
TIMEOUT      = 1
MAX_THREADS  = 100
HISTORY_FILE = os.path.expanduser("~/.hbscan_history.json")

COMMON_PORTS = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB",
    3306:"MySQL", 3389:"RDP", 5900:"VNC", 8080:"HTTP-Alt",
    8443:"HTTPS-Alt", 27017:"MongoDB", 137:"NetBIOS", 139:"NetBIOS",
    161:"SNMP", 389:"LDAP", 636:"LDAPS", 993:"IMAPS", 995:"POP3S",
    587:"SMTP-TLS", 1433:"MSSQL", 1521:"Oracle", 5432:"PostgreSQL",
    6379:"Redis", 9200:"ElasticSearch", 2181:"ZooKeeper", 11211:"Memcached"
}

RISK_LEVELS = {
    21:"HIGH", 22:"MED", 23:"HIGH", 25:"MED", 53:"LOW",
    80:"LOW", 110:"MED", 143:"MED", 443:"LOW", 445:"HIGH",
    3306:"HIGH", 3389:"HIGH", 5900:"HIGH", 137:"HIGH",
    139:"HIGH", 161:"MED", 389:"MED", 27017:"HIGH"
}

RISK_COLOR = {"HIGH": C.RED, "MED": C.YELLOW, "LOW": C.GREEN}

UDP_PORTS = {
    53:"DNS", 67:"DHCP", 68:"DHCP", 69:"TFTP", 123:"NTP",
    137:"NetBIOS", 161:"SNMP", 500:"IKE", 514:"Syslog",
    1194:"OpenVPN", 5353:"mDNS"
}

open_ports = []
udp_open   = []
lock       = threading.Lock()

# ─────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────
def print_banner():
    os.system("clear" if os.name == "posix" else "cls")
    print()
    print(C.CYAN   +C.BOLD+ "  ██╗  ██╗██████╗ ███████╗ ██████╗ █████╗ ███╗  ██╗" +C.RESET)
    print(C.CYAN   +C.BOLD+ "  ██║  ██║██╔══██╗██╔════╝██╔════╝██╔══██╗████╗ ██║" +C.RESET)
    print(C.BLUE   +C.BOLD+ "  ███████║██████╔╝███████╗██║     ███████║██╔██╗██║"  +C.RESET)
    print(C.BLUE   +C.BOLD+ "  ██╔══██║██╔══██╗╚════██║██║     ██╔══██║██║╚████║" +C.RESET)
    print(C.MAGENTA+C.BOLD+ "  ██║  ██║██████╔╝███████║╚██████╗██║  ██║██║ ╚███║" +C.RESET)
    print(C.MAGENTA+C.BOLD+ "  ╚═╝  ╚═╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝"+C.RESET)
    print()
    print(C.YELLOW+C.BOLD +  "        HawkByte Network Scanner  v" + VERSION +C.RESET)
    print(C.DIM+C.WHITE   +  "        Educational Use Only — Scan Legal Targets" +C.RESET)
    print()
    print(C.DIM + "  " + "─"*51 + C.RESET)
    print(C.GREEN+"  [+] "+C.WHITE+"Version : "+C.CYAN+VERSION+C.RESET)
    print(C.GREEN+"  [+] "+C.WHITE+"Platform: "+C.CYAN+sys.platform+C.RESET)
    print(C.GREEN+"  [+] "+C.WHITE+"Python  : "+C.CYAN+sys.version.split()[0]+C.RESET)
    print(C.DIM + "  " + "─"*51 + C.RESET)
    print()

# ─────────────────────────────────────────
#  RESOLVE HOST
# ─────────────────────────────────────────
def resolve_host(target):
    try:
        return socket.gethostbyname(target)
    except:
        print(C.RED+f"\n  [!] Cannot resolve: {target}"+C.RESET)
        sys.exit(1)

# ─────────────────────────────────────────
#  FIX: PING — proper latency output
# ─────────────────────────────────────────
def ping_host(ip):
    try:
        param = "-n" if sys.platform == "win32" else "-c"
        r = subprocess.run(
            ["ping", param, "1", "-W", "2", ip],
            capture_output=True, text=True, timeout=5
        )
        output = r.stdout + r.stderr
        if r.returncode == 0:
            # Extract time= value
            for token in output.split():
                if token.startswith("time="):
                    lat = token.replace("time=", "").replace("ms","").strip()
                    return True, f"{lat}ms"
                if token.startswith("time<"):
                    return True, "<1ms"
            return True, "alive"
        return False, "unreachable"
    except:
        return False, "timeout"

def measure_latency(ip, port):
    try:
        s = socket.socket(); s.settimeout(TIMEOUT)
        t = time.time(); s.connect_ex((ip, port)); s.close()
        return round((time.time()-t)*1000, 2)
    except:
        return None

# ─────────────────────────────────────────
#  FIX: OS DETECTION — socket TTL fallback
# ─────────────────────────────────────────
def detect_os(ip):
    # Method 1: ping TTL
    try:
        param = "-n" if sys.platform == "win32" else "-c"
        r = subprocess.run(["ping", param, "1", ip],
                           capture_output=True, text=True, timeout=4)
        o = r.stdout.lower()
        if "ttl=64"  in o or "ttl=63"  in o: return "Linux / Unix / Android"
        if "ttl=128" in o or "ttl=127" in o: return "Windows"
        if "ttl=254" in o or "ttl=255" in o: return "Network Device (Router)"
        if "ttl=32"  in o: return "Windows 95/98"
        if "ttl=" in o:
            for tok in o.split():
                if "ttl=" in tok:
                    try:
                        ttl = int(tok.split("=")[1])
                        if ttl <= 64:   return "Linux / Unix"
                        if ttl <= 128:  return "Windows"
                        return f"Unknown (TTL={ttl})"
                    except: pass
    except: pass

    # Method 2: TCP port fingerprint
    win_ports  = [135, 139, 445, 3389]
    lin_ports  = [22, 111, 2049]
    win_open   = sum(1 for p in win_ports  if _tcp_check(ip, p))
    lin_open   = sum(1 for p in lin_ports  if _tcp_check(ip, p))
    if win_open >= 2: return "Windows (port-based)"
    if lin_open >= 1: return "Linux / Unix (port-based)"

    return "Unknown (ICMP blocked)"

def _tcp_check(ip, port):
    try:
        s = socket.socket(); s.settimeout(0.5)
        r = s.connect_ex((ip, port)); s.close()
        return r == 0
    except: return False

# ─────────────────────────────────────────
#  BANNER GRABBING
# ─────────────────────────────────────────
def grab_banner(ip, port):
    try:
        s = socket.socket(); s.settimeout(TIMEOUT)
        s.connect((ip, port))
        b = s.recv(1024).decode(errors="ignore").strip()
        s.close(); return b[:60]
    except: return ""

# ─────────────────────────────────────────
#  SSL INFO
# ─────────────────────────────────────────
def get_ssl_info(ip, port=443):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ss:
                cert   = ss.getpeercert()
                cipher = ss.cipher()
                info   = {
                    "Protocol": ss.version(),
                    "Cipher":   cipher[0] if cipher else "N/A",
                    "Bits":     str(cipher[2]) if cipher else "N/A"
                }
                if cert:
                    subj = dict(x[0] for x in cert.get("subject", []))
                    issr = dict(x[0] for x in cert.get("issuer",  []))
                    info["Subject"] = subj.get("commonName", "N/A")
                    info["Issuer"]  = issr.get("organizationName", "N/A")
                    info["Expires"] = cert.get("notAfter", "N/A")
                return info
    except: return None

# ─────────────────────────────────────────
#  HTTP HEADERS
# ─────────────────────────────────────────
def get_http_headers(ip, port=80, https=False):
    try:
        if https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(ip, port, timeout=3, context=ctx)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=3)
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        h = dict(resp.getheaders()); h["Status"] = resp.status
        conn.close(); return h
    except: return None

# ─────────────────────────────────────────
#  DNS LOOKUP
# ─────────────────────────────────────────
def dns_lookup(target):
    r = {}
    try:    r["A"]    = socket.gethostbyname(target)
    except: r["A"]    = "N/A"
    try:
        info = socket.getaddrinfo(target, None, socket.AF_INET6)
        r["AAAA"] = info[0][4][0] if info else "N/A"
    except: r["AAAA"] = "N/A"
    try:    r["PTR"]  = socket.gethostbyaddr(r["A"])[0]
    except: r["PTR"]  = "N/A"
    try:    r["FQDN"] = socket.getfqdn(target)
    except: r["FQDN"] = "N/A"
    return r

def reverse_dns(ip):
    try:    return socket.gethostbyaddr(ip)[0]
    except: return "N/A"

# ─────────────────────────────────────────
#  WHOIS
# ─────────────────────────────────────────
def whois_lookup(target):
    try:
        s = socket.socket(); s.settimeout(5)
        s.connect(("whois.iana.org", 43))
        s.send((target + "\r\n").encode())
        resp = b""
        while True:
            d = s.recv(4096)
            if not d: break
            resp += d
        s.close()
        result = {}
        for line in resp.decode(errors="ignore").split("\n")[:30]:
            if ":" in line and not line.startswith("%"):
                k, _, v = line.partition(":")
                result[k.strip()] = v.strip()
        return result
    except: return {"Error": "Whois lookup failed"}

# ─────────────────────────────────────────
#  GEOIP
# ─────────────────────────────────────────
def geoip_lookup(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,regionName,city,isp,org,as,query"
        req = urllib.request.Request(url, headers={"User-Agent": "HBScan/2.1"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except: return {"Error": "GeoIP failed"}

# ─────────────────────────────────────────
#  FIX: ASN LOOKUP — multiple APIs with fallback
# ─────────────────────────────────────────
def asn_lookup(ip):
    # Method 1: ipinfo.io
    try:
        url = f"https://ipinfo.io/{ip}/json"
        req = urllib.request.Request(url, headers={"User-Agent": "HBScan/2.1"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            if "org" in data:
                org = data["org"]  # e.g. "AS15169 Google LLC"
                parts = org.split(" ", 1)
                return {
                    "ASN":     parts[0] if len(parts) > 0 else "N/A",
                    "Name":    parts[1] if len(parts) > 1 else "N/A",
                    "Country": data.get("country", "N/A"),
                    "Region":  data.get("region", "N/A"),
                }
    except: pass

    # Method 2: GeoIP AS field
    try:
        geo = geoip_lookup(ip)
        if "as" in geo and geo["as"]:
            parts = geo["as"].split(" ", 1)
            return {
                "ASN":  parts[0] if len(parts) > 0 else "N/A",
                "Name": parts[1] if len(parts) > 1 else "N/A",
                "ISP":  geo.get("isp", "N/A"),
                "Org":  geo.get("org", "N/A"),
            }
    except: pass

    return {"Error": "ASN lookup failed (no internet access)"}

# ─────────────────────────────────────────
#  TRACEROUTE
# ─────────────────────────────────────────
def traceroute(target):
    try:
        cmd = ["tracert","-d","-h","15",target] if sys.platform=="win32" \
              else ["traceroute","-m","15","-n",target]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return r.stdout
    except FileNotFoundError:
        return "traceroute not installed. Run: sudo apt install traceroute"
    except subprocess.TimeoutExpired:
        return "Traceroute timed out."
    except Exception as e:
        return f"Error: {e}"

# ─────────────────────────────────────────
#  UDP SCAN
# ─────────────────────────────────────────
def scan_udp_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1); s.sendto(b"\x00"*8, (ip, port))
        try:
            s.recv(1024)
            with lock: udp_open.append((port, UDP_PORTS.get(port,"Unknown")))
        except socket.timeout:
            with lock: udp_open.append((port, UDP_PORTS.get(port,"Unknown")+" (open|filtered)"))
        s.close()
    except: pass

# ─────────────────────────────────────────
#  FIX: PING SWEEP — auto-resolve domain
# ─────────────────────────────────────────
def ping_sweep(network):
    live = []
    # Auto-resolve if domain entered instead of CIDR
    if "/" not in network:
        try:
            ip = socket.gethostbyname(network)
            # Make it a /24 range
            parts = ip.split(".")
            network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            print(C.YELLOW+f"\n  [*] Resolved to network: {network}"+C.RESET)
        except:
            print(C.RED+"  [!] Enter a valid IP range like: 192.168.1.0/24"+C.RESET)
            return []
    try:
        net   = ipaddress.IPv4Network(network, strict=False)
        hosts = list(net.hosts())
        print(C.YELLOW+f"\n  [*] Sweeping {len(hosts)} hosts in {network}..."+C.RESET)
        print(C.DIM+"  "+"─"*51+C.RESET)

        def check(ip):
            alive, lat = ping_host(str(ip))
            if alive:
                h = reverse_dns(str(ip))
                with lock:
                    live.append((str(ip), h, lat))
                    print(C.GREEN+f"  [UP]  "+C.WHITE+f"{str(ip):<18}"+
                          C.CYAN +f"{h[:25]:<27}"+C.YELLOW+lat+C.RESET)

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
            ex.map(check, hosts)

        print(C.DIM+"\n  "+"─"*51+C.RESET)
        print(C.GREEN+f"  [+] {len(live)} live host(s) found in {network}"+C.RESET)
        return live
    except ValueError as e:
        print(C.RED+f"  [!] Invalid range: {e}"+C.RESET)
        return []

# ─────────────────────────────────────────
#  TCP PORT SCAN
# ─────────────────────────────────────────
def scan_port(ip, port, total, counter):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT); result = s.connect_ex((ip, port)); s.close()
        with lock:
            counter[0] += 1
            pct = int((counter[0]/total)*40)
            bar = "█"*pct + "░"*(40-pct)
            print(C.DIM+f"\r  [{bar}] {counter[0]}/{total}"+C.RESET, end="", flush=True)
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            banner  = grab_banner(ip, port)
            latency = measure_latency(ip, port)
            risk    = RISK_LEVELS.get(port, "LOW")
            with lock:
                open_ports.append({"port":port,"service":service,
                                   "banner":banner,"latency":latency,"risk":risk})
                rc = RISK_COLOR.get(risk, C.WHITE)
                print(C.GREEN+f"\n  [OPEN] "+C.WHITE+f"Port {port:<6}"+
                      C.YELLOW+f"{service:<14}"+rc+f"[{risk}]"+
                      C.DIM+f" {banner[:35]}"+C.RESET)
    except: pass

def threaded_scan(ip, port_list):
    counter = [0]; total = len(port_list); threads = []
    for port in port_list:
        t = threading.Thread(target=scan_port, args=(ip,port,total,counter))
        threads.append(t); t.start()
        if len(threads) >= MAX_THREADS:
            for th in threads: th.join()
            threads = []
    for th in threads: th.join()
    print()

# ─────────────────────────────────────────
#  FIX: SCAN HISTORY — fixed save & load
# ─────────────────────────────────────────
def save_history(target, ip, results):
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                history = json.load(f)
        except: history = []

    entry = {
        "timestamp":  datetime.datetime.now().isoformat(),
        "target":     target,
        "ip":         ip,
        "os":         results.get("os","N/A"),
        "open_ports": len(results.get("open_ports",[])),
        "duration":   results.get("duration","N/A"),
        "location":   f"{results.get('geoip',{}).get('city','?')}, {results.get('geoip',{}).get('country','?')}",
    }
    history.append(entry)
    history = history[-20:]  # keep last 20
    try:
        with open(HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=2, default=str)
        print(C.DIM+f"  [*] Scan saved to history."+C.RESET)
    except Exception as e:
        print(C.RED+f"  [!] Could not save history: {e}"+C.RESET)

def show_history():
    if not os.path.exists(HISTORY_FILE):
        print(C.YELLOW+"\n  [!] No scan history yet. Run a Full Scan first."+C.RESET+"\n")
        return
    try:
        with open(HISTORY_FILE, "r") as f:
            history = json.load(f)
        if not history:
            print(C.YELLOW+"\n  [!] History is empty."+C.RESET+"\n")
            return
        print(C.BOLD+C.CYAN+"\n  ─── Scan History (Last 20) ───"+C.RESET)
        print(C.WHITE+f"  {'#':<4}{'Timestamp':<22}{'Target':<18}{'IP':<18}{'Open':<8}{'Location'}"+C.RESET)
        print(C.DIM+"  "+"─"*75+C.RESET)
        for i, e in enumerate(reversed(history), 1):
            print(C.CYAN  +f"  {i:<4}"+
                  C.WHITE +f"{e['timestamp'][:19]:<22}"+
                  C.YELLOW+f"{e['target'][:16]:<18}"+
                  C.GREEN +f"{e['ip']:<18}"+
                  C.MAGENTA+f"{e['open_ports']:<8}"+
                  C.DIM   +f"{e.get('location','N/A')}"+C.RESET)
        print()
    except Exception as e:
        print(C.RED+f"  [!] Could not read history: {e}"+C.RESET)

# ─────────────────────────────────────────
#  EXPORTS
# ─────────────────────────────────────────
def export_json(results, filename):
    try:
        with open(filename, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(C.GREEN+f"  [+] JSON saved: {filename}"+C.RESET)
    except Exception as e:
        print(C.RED+f"  [!] JSON failed: {e}"+C.RESET)

def export_txt(results, filename):
    try:
        with open(filename, "w") as f:
            f.write("="*60+"\n  HBScan v"+VERSION+" — Scan Report\n"+"="*60+"\n\n")
            for key in ["target","ip","hostname","os","timestamp","duration"]:
                f.write(f"  {key:<12}: {results.get(key,'N/A')}\n")
            geo = results.get("geoip", {})
            f.write(f"  {'Location':<12}: {geo.get('city','N/A')}, {geo.get('country','N/A')}\n")
            f.write(f"  {'ISP':<12}: {geo.get('isp','N/A')}\n\n")
            f.write("─"*60+"\n  OPEN PORTS\n"+"─"*60+"\n")
            f.write(f"  {'PORT':<8}{'SERVICE':<14}{'RISK':<8}{'LATENCY':<12}BANNER\n")
            for p in results.get("open_ports", []):
                lat = f"{p.get('latency','N/A')}ms"
                f.write(f"  {p['port']:<8}{p['service']:<14}{p['risk']:<8}{lat:<12}{p['banner']}\n")
        print(C.GREEN+f"  [+] TXT saved: {filename}"+C.RESET)
    except Exception as e:
        print(C.RED+f"  [!] TXT failed: {e}"+C.RESET)

def export_html(results, filename):
    rb = {"HIGH":"#ff4757","MED":"#ffa502","LOW":"#2ed573"}
    rows = ""
    for p in results.get("open_ports", []):
        c   = rb.get(p["risk"], "#888")
        lat = f"{p.get('latency','N/A')}ms"
        rows += (f"<tr><td><b>{p['port']}</b></td><td>{p['service']}</td>"
                 f"<td><span style='background:{c};color:#fff;padding:2px 8px;"
                 f"border-radius:4px;font-size:12px'>{p['risk']}</span></td>"
                 f"<td>{lat}</td><td style='color:#aaa;font-size:12px'>{p['banner']}</td></tr>")
    geo      = results.get("geoip", {})
    dns      = results.get("dns", {})
    ssl_info = results.get("ssl_info") or {}
    hdrs     = results.get("http_headers") or {}
    ssl_html = "".join(f"<tr><td><b>{k}</b></td><td>{v}</td></tr>" for k,v in ssl_info.items())
    hdr_html = "".join(f"<tr><td><b>{k}</b></td><td>{v}</td></tr>" for k,v in list(hdrs.items())[:10])
    udp_rows = "".join(f"<tr><td><b>{p}</b></td><td>{s}</td></tr>" for p,s in results.get("udp_ports",[]))
    asn      = results.get("asn", {})
    asn_html = "".join(f"<tr><td><b>{k}</b></td><td>{v}</td></tr>" for k,v in asn.items())

    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>HBScan — {results.get('target')}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',sans-serif;background:#0a0e1a;color:#e0e0e0;padding:30px}}
.card{{background:#111827;border-radius:12px;padding:24px;margin-bottom:20px;border:1px solid #1f2937}}
h2{{color:#7dd3fc;font-size:15px;margin-bottom:14px;border-bottom:1px solid #1f2937;padding-bottom:6px}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}
.item{{background:#1a2234;border-radius:8px;padding:12px}}
.label{{font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:1px}}
.value{{font-size:14px;color:#e0e0e0;margin-top:4px;word-break:break-all}}
table{{width:100%;border-collapse:collapse;font-size:14px}}
th{{text-align:left;padding:10px 12px;background:#1a2234;color:#7dd3fc;font-weight:600}}
td{{padding:9px 12px;border-bottom:1px solid #1a2234;color:#d1d5db}}
tr:hover td{{background:#1a2234}}
.logo{{font-size:32px;font-weight:800;color:#00d4ff;letter-spacing:3px}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}}
.stat{{text-align:center;background:#111827;border-radius:8px;padding:16px;border:1px solid #1f2937}}
.num{{font-size:32px;font-weight:700;color:#00d4ff}}
.slabel{{font-size:12px;color:#6b7280;margin-top:4px}}
footer{{text-align:center;color:#374151;font-size:12px;margin-top:30px}}
</style></head><body>
<div style="display:flex;align-items:center;gap:16px;margin-bottom:24px">
  <div class="logo">HBSCAN</div>
  <div>
    <div style="color:#e0e0e0;font-size:18px;font-weight:600">HawkByte Network Scanner v{VERSION}</div>
    <div style="color:#6b7280;font-size:13px">Educational Use Only — Scan Report</div>
  </div>
</div>
<div class="stats">
  <div class="stat"><div class="num">{len(results.get('open_ports',[]))}</div><div class="slabel">Open TCP Ports</div></div>
  <div class="stat"><div class="num">{len([p for p in results.get('open_ports',[]) if p['risk']=='HIGH'])}</div><div class="slabel">High Risk</div></div>
  <div class="stat"><div class="num">{len(results.get('udp_ports',[]))}</div><div class="slabel">UDP Ports</div></div>
  <div class="stat"><div class="num" style="font-size:16px">{results.get('os','N/A')[:16]}</div><div class="slabel">OS Detected</div></div>
</div>
<div class="card"><h2>Target Information</h2><div class="grid">
  <div class="item"><div class="label">Target</div><div class="value">{results.get('target')}</div></div>
  <div class="item"><div class="label">IP Address</div><div class="value">{results.get('ip')}</div></div>
  <div class="item"><div class="label">Hostname</div><div class="value">{results.get('hostname','N/A')}</div></div>
  <div class="item"><div class="label">OS</div><div class="value">{results.get('os','N/A')}</div></div>
  <div class="item"><div class="label">Location</div><div class="value">{geo.get('city','N/A')}, {geo.get('country','N/A')}</div></div>
  <div class="item"><div class="label">ISP</div><div class="value">{geo.get('isp','N/A')}</div></div>
  <div class="item"><div class="label">ASN</div><div class="value">{geo.get('as','N/A')}</div></div>
  <div class="item"><div class="label">Scan Time</div><div class="value">{results.get('timestamp','N/A')}</div></div>
</div></div>
<div class="card"><h2>DNS Records</h2><table>
  <tr><th>Record</th><th>Value</th></tr>
  <tr><td>A (IPv4)</td><td>{dns.get('A','N/A')}</td></tr>
  <tr><td>AAAA (IPv6)</td><td>{dns.get('AAAA','N/A')}</td></tr>
  <tr><td>PTR (Reverse DNS)</td><td>{dns.get('PTR','N/A')}</td></tr>
  <tr><td>FQDN</td><td>{dns.get('FQDN','N/A')}</td></tr>
</table></div>
<div class="card"><h2>Open TCP Ports</h2><table>
  <tr><th>Port</th><th>Service</th><th>Risk</th><th>Latency</th><th>Banner</th></tr>
  {rows if rows else "<tr><td colspan='5' style='text-align:center;color:#6b7280'>No open ports found</td></tr>"}
</table></div>
{"<div class='card'><h2>UDP Ports</h2><table><tr><th>Port</th><th>Service</th></tr>"+udp_rows+"</table></div>" if udp_rows else ""}
{"<div class='card'><h2>ASN Information</h2><table><tr><th>Field</th><th>Value</th></tr>"+asn_html+"</table></div>" if asn_html and "Error" not in asn_html else ""}
{"<div class='card'><h2>SSL / TLS Certificate</h2><table><tr><th>Field</th><th>Value</th></tr>"+ssl_html+"</table></div>" if ssl_html else ""}
{"<div class='card'><h2>HTTP Headers</h2><table><tr><th>Header</th><th>Value</th></tr>"+hdr_html+"</table></div>" if hdr_html else ""}
<footer>Generated by HBScan v{VERSION} — HawkByte Network Scanner — Educational Use Only</footer>
</body></html>"""

    try:
        with open(filename, "w") as f:
            f.write(html)
        print(C.GREEN+f"  [+] HTML saved: {filename}"+C.RESET)
    except Exception as e:
        print(C.RED+f"  [!] HTML failed: {e}"+C.RESET)

# ─────────────────────────────────────────
#  PRINT RESULTS
# ─────────────────────────────────────────
def print_results(results):
    print()
    print(C.DIM+"  "+"═"*57+C.RESET)
    print(C.BOLD+C.CYAN+"   SCAN COMPLETE — HBScan v"+VERSION+C.RESET)
    print(C.DIM+"  "+"═"*57+C.RESET)
    for label, key in [("Target","target"),("Hostname","hostname"),
                        ("OS","os"),("Time","timestamp"),("Duration","duration")]:
        print(C.WHITE+f"  {label:<10}: "+C.YELLOW+f"{results.get(key,'N/A')}"+C.RESET)
    geo = results.get("geoip", {})
    if "city" in geo:
        print(C.WHITE+f"  {'Location':<10}: "+C.YELLOW+f"{geo.get('city')}, {geo.get('country')}"+C.RESET)
        print(C.WHITE+f"  {'ISP':<10}: "+C.YELLOW+f"{geo.get('isp','N/A')}"+C.RESET)
        print(C.WHITE+f"  {'ASN':<10}: "+C.YELLOW+f"{geo.get('as','N/A')}"+C.RESET)
    print(C.WHITE+f"  {'Open':<10}: "+C.GREEN+
          f"{len(results['open_ports'])} TCP, {len(results.get('udp_ports',[]))} UDP"+C.RESET)
    print(C.DIM+"  "+"═"*57+C.RESET)

    if results["open_ports"]:
        print()
        print(C.BOLD+C.WHITE+f"  {'PORT':<8}{'SERVICE':<14}{'RISK':<8}{'LATENCY':<12}BANNER"+C.RESET)
        print(C.DIM+"  "+"─"*57+C.RESET)
        for p in sorted(results["open_ports"], key=lambda x: x["port"]):
            rc  = RISK_COLOR.get(p["risk"], C.WHITE)
            lat = f"{p['latency']}ms" if p.get("latency") else "N/A"
            print(C.GREEN  +f"  {p['port']:<8}"+
                  C.YELLOW +f"{p['service']:<14}"+
                  rc       +f"{p['risk']:<8}"+
                  C.CYAN   +f"{lat:<12}"+
                  C.DIM    +f"{p['banner'][:35]}"+C.RESET)

    if results.get("udp_ports"):
        print()
        print(C.BOLD+C.MAGENTA+"  UDP PORTS:"+C.RESET)
        for port, svc in results["udp_ports"]:
            print(C.MAGENTA+f"  {port:<8}"+C.WHITE+svc+C.RESET)
    print()

# ─────────────────────────────────────────
#  PORT RANGE MENU
# ─────────────────────────────────────────
def get_port_range():
    print(C.BOLD+C.WHITE+"\n  Select Scan Mode:"+C.RESET)
    print(C.CYAN   +"  [1]"+C.WHITE+" Quick    — Top common ports")
    print(C.CYAN   +"  [2]"+C.WHITE+" Standard — Ports 1–1024")
    print(C.YELLOW +"  [3]"+C.WHITE+" Full     — All 65535 ports (slow)")
    print(C.MAGENTA+"  [4]"+C.WHITE+" Custom   — Enter your own range"+C.RESET)
    print()
    ch = input(C.BOLD+C.GREEN+"  hbscan > "+C.RESET).strip()
    if ch == "1": return list(COMMON_PORTS.keys())
    elif ch == "2": return list(range(1, 1025))
    elif ch == "3":
        print(C.YELLOW+"\n  [!] Full scan may take several minutes..."+C.RESET)
        return list(range(1, 65536))
    elif ch == "4":
        s = int(input(C.CYAN+"  Start port: "+C.RESET))
        e = int(input(C.CYAN+"  End port  : "+C.RESET))
        return list(range(s, e+1))
    else:
        return list(COMMON_PORTS.keys())

# ─────────────────────────────────────────
#  FULL SCAN
# ─────────────────────────────────────────
def full_scan():
    global open_ports, udp_open
    open_ports = []; udp_open = []

    target = input(C.WHITE+"\n  Enter target (IP or hostname): "+C.RESET).strip()
    if not target: return

    ip = resolve_host(target)
    print(C.GREEN+f"\n  [*] Resolved   : "+C.CYAN+f"{target} → {ip}"+C.RESET)

    print(C.GREEN+f"  [*] Pinging    : "+C.RESET, end="")
    alive, lat = ping_host(ip)
    status = C.GREEN+"ALIVE" if alive else C.RED+"DOWN (may still be up)"
    print(status+C.YELLOW+f"  ({lat})"+C.RESET)

    print(C.GREEN+f"  [*] OS Detect  : "+C.RESET, end="", flush=True)
    os_d = detect_os(ip)
    print(C.CYAN+os_d+C.RESET)

    print(C.GREEN+f"  [*] Reverse DNS: "+C.RESET, end="")
    hostname = reverse_dns(ip)
    print(C.CYAN+hostname+C.RESET)

    print(C.GREEN+f"  [*] GeoIP      : "+C.RESET, end="")
    geo = geoip_lookup(ip)
    print(C.CYAN+(f"{geo.get('city')}, {geo.get('country')}" if "city" in geo else "N/A")+C.RESET)

    print(C.GREEN+f"  [*] ASN        : "+C.RESET, end="")
    asn = asn_lookup(ip)
    print(C.CYAN+(f"{asn.get('ASN','')} {asn.get('Name','')}" if "Error" not in asn else "N/A")+C.RESET)

    print(C.GREEN+f"  [*] DNS Records: "+C.RESET, end="")
    dns = dns_lookup(target)
    print(C.CYAN+dns.get('A','N/A')+C.RESET)

    print(C.GREEN+f"  [*] SSL Check  : "+C.RESET, end="")
    ssl_info = get_ssl_info(ip)
    print(C.CYAN+(f"{ssl_info.get('Protocol','?')} | {ssl_info.get('Subject','?')}" if ssl_info else "N/A")+C.RESET)

    print(C.GREEN+f"  [*] HTTP Hdrs  : "+C.RESET, end="")
    hdrs = get_http_headers(ip)
    srv  = hdrs.get("Server", hdrs.get("server", "N/A")) if hdrs else "N/A"
    print(C.CYAN+str(srv)+C.RESET)

    port_list = get_port_range()
    print(C.YELLOW+f"\n  [*] TCP Scanning {len(port_list)} ports on {ip}..."+C.RESET)
    print(C.DIM+"  "+"─"*51+C.RESET+"\n")

    t0 = time.time()
    threaded_scan(ip, port_list)

    print(C.YELLOW+f"  [*] UDP Scanning {len(UDP_PORTS)} ports..."+C.RESET)
    ut = [threading.Thread(target=scan_udp_port, args=(ip,p)) for p in UDP_PORTS]
    for t in ut: t.start()
    for t in ut: t.join()

    duration = round(time.time()-t0, 2)
    results  = {
        "target":      target,
        "ip":          ip,
        "hostname":    hostname,
        "os":          os_d,
        "geoip":       geo,
        "asn":         asn,
        "dns":         dns,
        "ssl_info":    ssl_info,
        "http_headers":hdrs,
        "open_ports":  open_ports,
        "udp_ports":   udp_open,
        "total_ports": len(port_list),
        "duration":    f"{duration}s",
        "timestamp":   datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    print_results(results)
    save_history(target, ip, results)

    # Export
    print(C.BOLD+C.WHITE+"  Export Results:"+C.RESET)
    print(C.CYAN+"  [1]"+C.WHITE+" HTML  "+C.CYAN+"[2]"+C.WHITE+" JSON  "+C.CYAN+"[3]"+C.WHITE+" TXT  "+C.CYAN+"[4]"+C.WHITE+" All  "+C.CYAN+"[0]"+C.WHITE+" Skip"+C.RESET)
    ch    = input(C.BOLD+C.GREEN+"\n  hbscan > "+C.RESET).strip()
    fname = f"hbscan_{ip.replace('.','_')}_{int(time.time())}"
    if ch in ("1","4"): export_html(results, fname+".html")
    if ch in ("2","4"): export_json(results, fname+".json")
    if ch in ("3","4"): export_txt (results, fname+".txt")
    print()

# ─────────────────────────────────────────
#  MAIN MENU
# ─────────────────────────────────────────
def main_menu():
    options = [
        ("1","Full Scan     ","All recon — ports, GeoIP, SSL, DNS"),
        ("2","Ping Sweep    ","Find live hosts in a network range"),
        ("3","DNS Lookup    ","Query DNS records of a domain     "),
        ("4","Traceroute    ","Trace network path to target      "),
        ("5","GeoIP + ASN   ","IP location, ISP & ASN info       "),
        ("6","SSL/TLS Info  ","Check HTTPS certificate details   "),
        ("7","HTTP Headers  ","Fetch server response headers     "),
        ("8","Whois Lookup  ","Domain registration info          "),
        ("9","Scan History  ","View last 20 scans                "),
    ]
    print(C.BOLD+C.WHITE+"  ┌─ SELECT MODE "+"─"*38+"┐"+C.RESET)
    for num, name, desc in options:
        print(C.CYAN+f"  │ [{num}] "+C.WHITE+f"{name}"+C.DIM+f"— {desc}"+C.CYAN+"│"+C.RESET)
    print(C.YELLOW+"  │ [0] Exit         "+" "*36+C.YELLOW+"│"+C.RESET)
    print(C.BOLD+C.WHITE+"  └"+"─"*53+"┘"+C.RESET)
    print()
    return input(C.BOLD+C.GREEN+"  hbscan > "+C.RESET).strip()

# ─────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────
def main():
    print_banner()
    while True:
        ch = main_menu()
        if ch == "1":
            full_scan()
        elif ch == "2":
            net = input(C.WHITE+"\n  Enter range (e.g. 192.168.1.0/24) or domain: "+C.RESET).strip()
            ping_sweep(net)
        elif ch == "3":
            t = input(C.WHITE+"\n  Enter domain: "+C.RESET).strip()
            dns = dns_lookup(t)
            print(C.BOLD+C.CYAN+"\n  ─── DNS Results ───"+C.RESET)
            for k,v in dns.items():
                print(C.YELLOW+f"  {k:<8}"+C.WHITE+f": {v}"+C.RESET)
            print()
        elif ch == "4":
            t = input(C.WHITE+"\n  Enter target: "+C.RESET).strip()
            print(C.YELLOW+"  [*] Running traceroute..."+C.RESET)
            print(C.DIM+traceroute(t)+C.RESET)
        elif ch == "5":
            ip  = input(C.WHITE+"\n  Enter IP: "+C.RESET).strip()
            geo = geoip_lookup(ip)
            asn = asn_lookup(ip)
            print(C.BOLD+C.CYAN+"\n  ─── GeoIP ───"+C.RESET)
            for k,v in geo.items():
                print(C.YELLOW+f"  {k:<14}"+C.WHITE+f": {v}"+C.RESET)
            print(C.BOLD+C.CYAN+"\n  ─── ASN ───"+C.RESET)
            for k,v in asn.items():
                print(C.YELLOW+f"  {k:<14}"+C.WHITE+f": {v}"+C.RESET)
            print()
        elif ch == "6":
            ip   = input(C.WHITE+"\n  Enter IP/hostname: "+C.RESET).strip()
            port = int(input(C.WHITE+"  Port [443]: "+C.RESET).strip() or "443")
            info = get_ssl_info(ip, port)
            print(C.BOLD+C.CYAN+"\n  ─── SSL/TLS Info ───"+C.RESET)
            if info:
                for k,v in info.items():
                    print(C.YELLOW+f"  {k:<12}"+C.WHITE+f": {v}"+C.RESET)
            else:
                print(C.RED+"  [!] No SSL info found."+C.RESET)
            print()
        elif ch == "7":
            ip   = input(C.WHITE+"\n  Enter IP/hostname: "+C.RESET).strip()
            port = int(input(C.WHITE+"  Port [80]: "+C.RESET).strip() or "80")
            hdrs = get_http_headers(ip, port)
            print(C.BOLD+C.CYAN+"\n  ─── HTTP Headers ───"+C.RESET)
            if hdrs:
                for k,v in hdrs.items():
                    print(C.YELLOW+f"  {str(k):<26}"+C.WHITE+f": {v}"+C.RESET)
            else:
                print(C.RED+"  [!] Could not fetch headers."+C.RESET)
            print()
        elif ch == "8":
            t = input(C.WHITE+"\n  Enter domain/IP: "+C.RESET).strip()
            print(C.YELLOW+"  [*] Whois lookup..."+C.RESET)
            info = whois_lookup(t)
            print(C.BOLD+C.CYAN+"\n  ─── Whois Results ───"+C.RESET)
            for k,v in list(info.items())[:15]:
                print(C.YELLOW+f"  {k:<22}"+C.WHITE+f": {v}"+C.RESET)
            print()
        elif ch == "9":
            show_history()
        elif ch == "0":
            print(C.CYAN+"\n  Goodbye! Stay legal. 🦅\n"+C.RESET)
            sys.exit(0)
        else:
            print(C.RED+"  [!] Invalid choice.\n"+C.RESET)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(C.RED+"\n\n  [!] Interrupted. Exiting HBScan.\n"+C.RESET)
        sys.exit(0)