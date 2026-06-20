#!/usr/bin/env python3
"""
NetScope — Network Analyzer
A zero-dependency web app (Python standard library only).

Run:  python3 app.py
Then open http://127.0.0.1:8000 in your browser.
"""

import json
import os
import re
import ssl
import time
import socket
import ipaddress
import subprocess
import http.client
import urllib.request
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

HOST = "127.0.0.1"
PORT = 8000
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

# ---------------------------------------------------------------------------
# Security: validate the user-supplied target so we never pass junk to a shell.
# We always call subprocess with a list (no shell=True), but we still validate.
# ---------------------------------------------------------------------------
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def validate_target(target: str) -> str:
    target = (target or "").strip()
    if not target:
        raise ValueError("Cible vide.")
    if len(target) > 253:
        raise ValueError("Cible trop longue.")
    target = re.sub(r"^[a-zA-Z]+://", "", target)
    target = target.split("/")[0].split("?")[0].split(":")[0]
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    if not HOSTNAME_RE.match(target):
        raise ValueError("Nom de domaine ou adresse IP invalide.")
    return target


def is_public_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return not (obj.is_private or obj.is_loopback or obj.is_link_local
                    or obj.is_multicast or obj.is_reserved or obj.is_unspecified)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# GeoIP lookup via the free ip-api.com batch endpoint (no key required).
# ---------------------------------------------------------------------------
def geolocate(ips):
    public = list(dict.fromkeys(ip for ip in ips if is_public_ip(ip)))
    if not public:
        return {}
    payload = [{"query": ip,
                "fields": "status,country,countryCode,city,lat,lon,isp,query"}
               for ip in public]
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        "http://ip-api.com/batch", data=body,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.load(resp)
    except Exception:
        return {}
    return {d["query"]: d for d in data if d.get("status") == "success"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def run(args, timeout):
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return (proc.stdout or "") + (proc.stderr or "")
    except FileNotFoundError:
        return f"ERROR: commande introuvable: {args[0]}"
    except subprocess.TimeoutExpired:
        return "ERROR: délai dépassé."


def _parse_cert_date(s):
    if not s:
        return None
    try:
        dt = datetime.strptime(s.replace(" GMT", ""), "%b %d %H:%M:%S %Y")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Network tools
# ---------------------------------------------------------------------------
def tool_ping(target):
    out = run(["ping", "-c", "4", "-W", "2", target], timeout=20)
    loss, avg = None, None
    m = re.search(r"(\d+(?:\.\d+)?)% packet loss", out)
    if m:
        loss = float(m.group(1))
    m = re.search(r"=\s*[\d.]+/([\d.]+)/", out)
    if m:
        avg = float(m.group(1))
    return {"raw": out, "loss": loss, "avg_ms": avg}


def tool_traceroute(target):
    out = run(["traceroute", "-n", "-w", "1", "-q", "1", "-m", "30", target], timeout=90)
    hops = []
    for line in out.splitlines():
        m = re.match(r"\s*(\d+)\s+(.*)", line)
        if not m:
            continue
        rest = m.group(2)
        ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", rest)
        rtt_match = re.search(r"([\d.]+)\s*ms", rest)
        hops.append({
            "hop": int(m.group(1)),
            "ip": ip_match.group(1) if ip_match else None,
            "rtt_ms": float(rtt_match.group(1)) if rtt_match else None,
        })
    # Auto-stop: trim trailing hops that never answered (the '*' lines up to 30),
    # so we only show the meaningful part of the route.
    while len(hops) > 1 and hops[-1]["ip"] is None:
        hops.pop()
    geo = geolocate([h["ip"] for h in hops if h["ip"]])
    for h in hops:
        g = geo.get(h["ip"]) if h["ip"] else None
        if g:
            h.update({"country": g.get("country"), "countryCode": g.get("countryCode"),
                      "city": g.get("city"), "isp": g.get("isp"),
                      "lat": g.get("lat"), "lon": g.get("lon")})
        elif h["ip"] and not is_public_ip(h["ip"]):
            h["country"] = "Réseau privé / local"
    return {"raw": out, "hops": hops}


def tool_whois(target):
    out = run(["whois", target], timeout=20)
    fields = {}
    for key in ["Registrar", "Creation Date", "Registry Expiry Date", "Updated Date",
                "Registrant Organization", "Registrant Country", "Domain Name", "Name Server"]:
        m = re.search(rf"^{re.escape(key)}:\s*(.+)$", out, re.IGNORECASE | re.MULTILINE)
        if m:
            fields[key] = m.group(1).strip()
    return {"raw": out, "fields": fields}


# All DNS record types the user can query (allowlist — never pass raw input to dig)
DNS_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "SRV",
             "CAA", "DNSKEY", "DS", "NAPTR", "TLSA", "SPF", "HINFO"]
DNS_DEFAULT = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]


def tool_dns(target, rtype=None):
    rtype = (rtype or "").upper()
    if rtype and rtype != "ALL":
        if rtype not in DNS_TYPES:
            return {"error": "Type DNS non supporté."}
        types = [rtype]
    else:
        types = DNS_DEFAULT
    single = len(types) == 1
    records = {}
    for t in types:
        out = run(["dig", "+short", t, target], timeout=15)
        values = [ln.strip() for ln in out.splitlines() if ln.strip() and not ln.startswith("ERROR")]
        if values or single:
            records[t] = values
    return {"records": records, "single": single, "rtype": rtype or "ALL"}


def tool_rdns(target):
    try:
        ip = target if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target) else socket.gethostbyname(target)
    except Exception:
        return {"error": f"Résolution impossible pour {target}."}
    try:
        name, aliases, _ = socket.gethostbyaddr(ip)
        return {"ip": ip, "hostname": name, "aliases": aliases}
    except Exception:
        return {"ip": ip, "hostname": None, "aliases": []}


COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}


def check_port(host, port, timeout=1.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def tool_port(target, ports=None):
    if ports:
        port_list = sorted({int(p) for p in ports if 0 < int(p) <= 65535})[:1024]
    else:
        port_list = sorted(COMMON_PORTS.keys())
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        return {"error": f"Résolution impossible pour {target}.", "results": []}
    results = []
    with ThreadPoolExecutor(max_workers=64) as ex:
        futs = {ex.submit(check_port, target, p): p for p in port_list}
        for fut in as_completed(futs):
            p = futs[fut]
            results.append({"port": p, "service": COMMON_PORTS.get(p, ""), "open": fut.result()})
    results.sort(key=lambda r: r["port"])
    return {"ip": ip, "results": results}


def tool_ssl(target):
    port = 443
    info = {"host": target, "port": port}
    cert = None
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((target, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                info["protocol"] = ssock.version()
                info["cipher"] = ssock.cipher()[0]
                info["valid"] = True
    except ssl.SSLCertVerificationError as e:
        info["valid"] = False
        info["error"] = getattr(e, "verify_message", None) or str(e)
        info.update(_openssl_cert(target, port))
        return info
    except Exception as e:
        return {"error": f"Connexion SSL impossible: {e}"}

    if cert:
        subj = {k: v for rdn in cert.get("subject", ()) for k, v in rdn}
        iss = {k: v for rdn in cert.get("issuer", ()) for k, v in rdn}
        info["subject"] = subj.get("commonName")
        info["issuer"] = iss.get("organizationName") or iss.get("commonName")
        info["notBefore"] = cert.get("notBefore")
        info["notAfter"] = cert.get("notAfter")
        info["san"] = [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"]
        exp = _parse_cert_date(cert.get("notAfter"))
        if exp:
            info["days_left"] = (exp - datetime.now(timezone.utc)).days
    return info


def _openssl_cert(target, port):
    """Fallback for invalid certs: pull dates/issuer via openssl."""
    out = {}
    try:
        p1 = subprocess.Popen(
            ["openssl", "s_client", "-connect", f"{target}:{port}", "-servername", target],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        p2 = subprocess.Popen(
            ["openssl", "x509", "-noout", "-dates", "-issuer", "-subject"],
            stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        p1.stdout.close()
        text, _ = p2.communicate(timeout=10)
    except Exception:
        return out
    for line in (text or "").splitlines():
        if line.startswith("notAfter="):
            out["notAfter"] = line.split("=", 1)[1].strip()
        elif line.startswith("notBefore="):
            out["notBefore"] = line.split("=", 1)[1].strip()
        elif line.startswith("issuer="):
            m = re.search(r"O\s*=\s*([^,/]+)", line)
            out["issuer"] = m.group(1).strip() if m else line.split("=", 1)[1][:60]
        elif line.startswith("subject="):
            m = re.search(r"CN\s*=\s*([^,/]+)", line)
            out["subject"] = m.group(1).strip() if m else None
    exp = _parse_cert_date(out.get("notAfter"))
    if exp:
        out["days_left"] = (exp - datetime.now(timezone.utc)).days
    return out


def tool_http(target):
    chain = []
    scheme, host, path = "https", target, "/"
    for _ in range(6):
        Conn = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
        try:
            t0 = time.time()
            conn = Conn(host, timeout=10,
                        context=ssl._create_unverified_context() if scheme == "https" else None) \
                if scheme == "https" else Conn(host, timeout=10)
            conn.request("GET", path, headers={"User-Agent": "NetScope/1.0"})
            resp = conn.getresponse()
            elapsed = round((time.time() - t0) * 1000, 1)
            headers = {k: v for k, v in resp.getheaders()}
            location = resp.getheader("Location")
            resp.read(1)
            conn.close()
        except Exception as e:
            if scheme == "https" and not chain:
                scheme = "http"  # retry plain http on first failure
                continue
            return {"error": f"Requête HTTP impossible: {e}", "chain": chain}
        chain.append({"url": f"{scheme}://{host}{path}", "status": resp.status,
                      "reason": resp.reason, "ms": elapsed,
                      "server": headers.get("Server"),
                      "content_type": headers.get("Content-Type")})
        if location and resp.status in (301, 302, 303, 307, 308) and len(chain) < 6:
            loc = re.sub(r"^([a-z]+)://", "", location)
            scheme = "https" if location.startswith("https") else ("http" if location.startswith("http") else scheme)
            host = loc.split("/")[0].split(":")[0]
            path = "/" + loc.split("/", 1)[1] if "/" in loc else "/"
            continue
        break
    final = chain[-1] if chain else {}
    return {"chain": chain, "final": final}


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------
TOOLS = {
    "ping": tool_ping, "traceroute": tool_traceroute, "whois": tool_whois,
    "dns": tool_dns, "port": tool_port, "ssl": tool_ssl, "http": tool_http,
    "rdns": tool_rdns,
}


class Handler(BaseHTTPRequestHandler):
    server_version = "NetScope/2.0"

    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path, ctype):
        try:
            with open(path, "rb") as f:
                body = f.read()
        except FileNotFoundError:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        route = self.path.split("?")[0]
        files = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/index.html": ("index.html", "text/html; charset=utf-8"),
            "/style.css": ("style.css", "text/css"),
            "/app.js": ("app.js", "application/javascript"),
        }
        if route in files:
            name, ctype = files[route]
            self._file(os.path.join(STATIC_DIR, name), ctype)
        else:
            self.send_error(404)

    def do_POST(self):
        route = self.path.split("?")[0]
        if not route.startswith("/api/"):
            self.send_error(404)
            return
        tool = route[len("/api/"):]
        if tool not in TOOLS:
            self._json({"error": "Outil inconnu."}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(length) or b"{}")
            target = validate_target(data.get("target", ""))
        except ValueError as e:
            self._json({"error": str(e)}, 400)
            return
        except Exception:
            self._json({"error": "Requête invalide."}, 400)
            return
        try:
            if tool == "port":
                result = tool_port(target, data.get("ports"))
            elif tool == "dns":
                result = tool_dns(target, data.get("rtype"))
            else:
                result = TOOLS[tool](target)
            result["target"] = target
            self._json(result)
        except Exception as e:
            self._json({"error": f"Erreur interne: {e}"}, 500)


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"\n  NetScope — Network Analyzer")
    print(f"  http://{HOST}:{PORT}\n")
    print("  Ctrl+C pour arrêter.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Arrêté.")
        server.shutdown()


if __name__ == "__main__":
    main()
