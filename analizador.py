#!/usr/bin/env python3

import sys
import os
import re
import ssl
import argparse
import email
import time
from email import policy
from email.utils import parseaddr
from typing import Dict, Any, List, Optional, Tuple

import urllib.request
import urllib.error
import urllib.parse
import json
import base64
import ipaddress
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.prompt import Prompt
    from rich import box
except ImportError:
    print("Error: La librería 'rich' no está instalada.")
    print("Por favor instálala ejecutando: pip install rich")
    sys.exit(1)

console = Console()

SUSPICIOUS_KEYWORDS = [
    "urgente", "suspensión", "cuenta bloqueada", "verificar cuenta", 
    "actualizar datos", "banco", "clave caducada", "tarjeta", "seguridad", 
    "acceso no autorizado", "haga clic aquí", "inicie sesión", "premio",
    "factura pendiente", "pago rechazado", "multa", "password", "urgent",
    "transferencia", "confidencial", "tasa de aduana", "retenido",
    "recibo de sueldo", "cbu", "no puedo hablar", "desbloquee"
]

EXECUTIVE_KEYWORDS = [
    "gerencia", "director", "ceo", "presidente", "finanzas", 
    "tesoreria", "recursos humanos", "rrhh", "soporte", "seguridad"
]


def extract_links_from_html(html_content: str) -> List[str]:
    """Extrae enlaces href de contenido HTML."""
    return re.findall(r'href=[\'"]([^\'"]+)[\'"]', html_content, re.IGNORECASE)


def extract_links_from_text(text: str) -> List[str]:
    """Extrae URLs de texto plano."""
    return re.findall(r'https?://[^\s<>"\'\)]+', text, re.IGNORECASE)


def extract_ips_from_text(text: str) -> List[str]:
    """Extrae direcciones IPv4 válidas de un texto."""
    candidates = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    valid_ips = []
    for c in candidates:
        try:
            ipaddress.IPv4Address(c)
            # Evitar máscaras de subred comunes como 255.255.255.0
            if c not in ["255.255.255.0", "255.255.255.255", "0.0.0.0"]:
                valid_ips.append(c)
        except ValueError:
            continue
    return list(dict.fromkeys(valid_ips))


def parse_authentication_results(header_val: str) -> Dict[str, Any]:
    """
    Parsea la cabecera Authentication-Results (RFC 7601).
    Extrae resultados y dominios de SPF, DKIM y DMARC.
    """
    clean_header = " ".join(header_val.split())
    
    # SPF
    spf_res = "none"
    spf_domain = ""
    m_spf = re.search(r'\bspf=([a-z]+)', clean_header, re.IGNORECASE)
    if m_spf:
        spf_res = m_spf.group(1).lower()
    m_spf_domain = re.search(r'smtp\.mailfrom=([^\s;]+)', clean_header, re.IGNORECASE)
    if m_spf_domain:
        spf_domain = m_spf_domain.group(1).split("@")[-1].strip()

    # DKIM
    dkim_res = "none"
    dkim_domain = ""
    m_dkim = re.search(r'\bdkim=([a-z]+)', clean_header, re.IGNORECASE)
    if m_dkim:
        dkim_res = m_dkim.group(1).lower()
    m_dkim_domain = re.search(r'header\.d=([^\s;]+)', clean_header, re.IGNORECASE)
    if m_dkim_domain:
        dkim_domain = m_dkim_domain.group(1).strip()

    # DMARC
    dmarc_res = "none"
    dmarc_policy = ""
    dmarc_domain = ""
    m_dmarc = re.search(r'\bdmarc=([a-z]+)', clean_header, re.IGNORECASE)
    if m_dmarc:
        dmarc_res = m_dmarc.group(1).lower()
    m_dmarc_pol = re.search(r'\(p=([a-z]+)\)', clean_header, re.IGNORECASE)
    if m_dmarc_pol:
        dmarc_policy = m_dmarc_pol.group(1).lower()
    m_dmarc_domain = re.search(r'header\.from=([^\s;]+)', clean_header, re.IGNORECASE)
    if m_dmarc_domain:
        dmarc_domain = m_dmarc_domain.group(1).strip()

    return {
        "spf_result": spf_res,
        "spf_domain": spf_domain,
        "dkim_result": dkim_res,
        "dkim_domain": dkim_domain,
        "dmarc_result": dmarc_res,
        "dmarc_policy": dmarc_policy,
        "dmarc_domain": dmarc_domain,
    }


def parse_eml_file(filepath: str) -> Dict[str, Any]:
    """Parsea un archivo de correo electrónico estándar en formato EML."""
    with open(filepath, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    from_header = msg.get("From", "")
    to_header = msg.get("To", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    subject = msg.get("Subject", "")
    date = msg.get("Date", "")
    message_id = msg.get("Message-ID", "")
    
    # Extraer nombre y correo del From
    from_name, from_email = parseaddr(from_header)
    from_domain = from_email.split("@")[-1].lower() if "@" in from_email else ""

    _, reply_to_email = parseaddr(reply_to)
    reply_to_domain = reply_to_email.split("@")[-1].lower() if "@" in reply_to_email else ""

    _, to_email = parseaddr(to_header)
    to_domain = to_email.split("@")[-1].lower() if "@" in to_email else ""

    # Extraer IP de origen de la cabecera Received más reciente
    source_ip = ""
    received_headers = msg.get_all("Received", [])
    if received_headers:
        m_ip = re.search(r'\[([0-9a-fA-F:\.]+)\]', received_headers[0])
        if m_ip:
            source_ip = m_ip.group(1)

    # Extraer autenticación desde Authentication-Results
    auth_header = msg.get("Authentication-Results", "")
    if auth_header:
        auth_data = parse_authentication_results(auth_header)
    else:
        auth_data = {
            "spf_result": "none",
            "spf_domain": from_domain,
            "dkim_result": "none",
            "dkim_domain": from_domain,
            "dmarc_result": "none",
            "dmarc_policy": "",
            "dmarc_domain": from_domain,
        }
        rec_spf = msg.get("Received-SPF", "")
        if rec_spf:
            m = re.match(r"^([a-z]+)", rec_spf.strip(), re.IGNORECASE)
            if m:
                auth_data["spf_result"] = m.group(1).lower()

    if not auth_data["dmarc_domain"]:
        auth_data["dmarc_domain"] = from_domain

    # Extraer cuerpo, enlaces e IPs
    body_text = ""
    all_links = []
    
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            try:
                content = part.get_content()
                if isinstance(content, str):
                    if ctype == "text/plain":
                        body_text += "\n" + content
                        all_links.extend(extract_links_from_text(content))
                    elif ctype == "text/html":
                        all_links.extend(extract_links_from_html(content))
                        all_links.extend(extract_links_from_text(content))
                        clean_content = re.sub(r'<[^>]+>', ' ', content)
                        body_text += "\n" + clean_content
            except Exception:
                pass
    else:
        try:
            content = msg.get_content()
            if isinstance(content, str):
                body_text = content
                if msg.get_content_type() == "text/html":
                    all_links.extend(extract_links_from_html(content))
                    all_links.extend(extract_links_from_text(content))
                    body_text = re.sub(r'<[^>]+>', ' ', body_text)
                else:
                    all_links.extend(extract_links_from_text(content))
        except Exception:
            pass

    # Depurar y deduplicar enlaces (filtrando namespaces XML y URLs técnicas)
    IGNORED_SCHEMAS = ["w3.org", "schemas.microsoft.com", "schemas.openxmlformats.org", "xml.org"]
    clean_links = []
    for l in all_links:
        l = l.strip().rstrip('.,;\'")>')
        if l and not any(ign in l.lower() for ign in IGNORED_SCHEMAS):
            if l not in clean_links:
                clean_links.append(l)

    # Identificar IPs encontradas
    detected_ips = []
    if source_ip:
        detected_ips.append(source_ip)
    for ip in extract_ips_from_text(body_text):
        if ip not in detected_ips:
            detected_ips.append(ip)

    return {
        "file": os.path.basename(filepath),
        "from_raw": from_header,
        "from_name": from_name,
        "from_email": from_email,
        "from_domain": from_domain,
        "to_raw": to_header,
        "to_email": to_email,
        "to_domain": to_domain,
        "reply_to": reply_to,
        "reply_to_email": reply_to_email,
        "reply_to_domain": reply_to_domain,
        "return_path": return_path,
        "subject": subject,
        "date": date,
        "message_id": message_id,
        "source_ip": source_ip,
        "detected_ips": detected_ips,
        "spf_result": auth_data["spf_result"],
        "spf_domain": auth_data["spf_domain"] or from_domain,
        "dkim_result": auth_data["dkim_result"],
        "dkim_domain": auth_data["dkim_domain"] or from_domain,
        "dmarc_result": auth_data["dmarc_result"],
        "dmarc_policy": auth_data["dmarc_policy"],
        "dmarc_domain": auth_data["dmarc_domain"] or from_domain,
        "body": body_text.strip(),
        "links": clean_links,
    }


# ============================================================================
# MÓDULO DE INTEGRACIÓN CON VIRUSTOTAL API v3
# ============================================================================

def get_ssl_context():
    """Genera un contexto SSL compatible con macOS y certificados del sistema."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        try:
            return ssl.create_default_context()
        except Exception:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx


def vt_lookup_url(url: str, api_key: str) -> Dict[str, Any]:
    """
    Consulta el reporte de una URL en VirusTotal API v3.
    Identificador: Base64 URL-safe de la URL sin padding '=' (RFC 4648).
    Docs: https://docs.virustotal.com/reference/url-info
    """
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    req = urllib.request.Request(api_url, headers={
        "x-apikey": api_key,
        "User-Agent": "Email-Auth-Analyzer/1.0"
    })
    
    try:
        with urllib.request.urlopen(req, context=get_ssl_context(), timeout=12) as response:
            data = json.loads(response.read().decode())
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "target": url,
                "type": "URL",
                "status": "success",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attrs.get("reputation", 0),
                "title": attrs.get("title", ""),
                "categories": list(attrs.get("categories", {}).values())[:2],
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return vt_submit_url_scan(url, api_key)
        elif e.code == 401:
            return {"target": url, "type": "URL", "status": "error", "message": "API Key inválida o no autorizada"}
        elif e.code == 429:
            return {"target": url, "type": "URL", "status": "error", "message": "Cuota de VirusTotal excedida (Rate Limit)"}
        return {"target": url, "type": "URL", "status": "error", "message": f"Error HTTP {e.code}"}
    except Exception as e:
        return {"target": url, "type": "URL", "status": "error", "message": str(e)}


def vt_submit_url_scan(url: str, api_key: str) -> Dict[str, Any]:
    """
    Envía una URL nueva a escanear a VirusTotal si no existía reporte previo.
    Docs: https://docs.virustotal.com/reference/scan-url
    """
    api_url = "https://www.virustotal.com/api/v3/urls"
    data = urllib.parse.urlencode({"url": url}).encode()
    req = urllib.request.Request(api_url, data=data, headers={
        "x-apikey": api_key,
        "User-Agent": "Email-Auth-Analyzer/1.0"
    })
    try:
        with urllib.request.urlopen(req, context=get_ssl_context(), timeout=12) as response:
            return {
                "target": url,
                "type": "URL",
                "status": "submitted",
                "message": "Enviada a escaneo en VirusTotal (análisis en progreso)"
            }
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {"target": url, "type": "URL", "status": "error", "message": "API Key inválida o no autorizada"}
        return {"target": url, "type": "URL", "status": "not_found", "message": f"Sin reporte previo (HTTP {e.code})"}
    except Exception as e:
        return {"target": url, "type": "URL", "status": "not_found", "message": "Sin reporte previo en VirusTotal"}


def vt_lookup_ip(ip: str, api_key: str) -> Dict[str, Any]:
    """
    Consulta la reputación de una dirección IP en VirusTotal API v3.
    Docs: https://docs.virustotal.com/reference/ip-info
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_loopback or ip.startswith("10.") or ip.startswith("192.168.") or (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31):
            return {
                "target": ip,
                "type": "IP",
                "status": "private",
                "message": "IP privada / red local (RFC 1918) - No enrutable en Internet"
            }
    except ValueError:
        pass

    api_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    req = urllib.request.Request(api_url, headers={
        "x-apikey": api_key,
        "User-Agent": "Email-Auth-Analyzer/1.0"
    })
    
    try:
        with urllib.request.urlopen(req, context=get_ssl_context(), timeout=12) as response:
            data = json.loads(response.read().decode())
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "target": ip,
                "type": "IP",
                "status": "success",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attrs.get("reputation", 0),
                "as_owner": attrs.get("as_owner", "N/A"),
                "country": attrs.get("country", "N/A"),
                "network": attrs.get("network", "N/A"),
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"target": ip, "type": "IP", "status": "not_found", "message": "Sin registros en VirusTotal"}
        elif e.code == 401:
            return {"target": ip, "type": "IP", "status": "error", "message": "API Key inválida o no autorizada"}
        elif e.code == 429:
            return {"target": ip, "type": "IP", "status": "error", "message": "Cuota de VirusTotal excedida (Rate Limit)"}
        return {"target": ip, "type": "IP", "status": "error", "message": f"Error HTTP {e.code}"}
    except Exception as e:
        return {"target": ip, "type": "IP", "status": "error", "message": str(e)}


def analyze_iocs_with_virustotal(data: Dict[str, Any], api_key: Optional[str]) -> List[Dict[str, Any]]:
    """Analiza todas las URLs e IPs encontradas utilizando VirusTotal."""
    results = []
    targets_urls = data.get("links", [])
    targets_ips = data.get("detected_ips", [])

    if not api_key:
        # Registrar IoCs identificados para mostrarlos aunque no haya API key
        for u in targets_urls:
            results.append({"target": u, "type": "URL", "status": "no_key", "message": "Omitido (sin API Key)"})
        for ip in targets_ips:
            results.append({"target": ip, "type": "IP", "status": "no_key", "message": "Omitido (sin API Key)"})
        return results

    total_iocs = len(targets_urls) + len(targets_ips)
    if total_iocs > 0:
        console.print(f"[bold cyan]🔍 Consultando VirusTotal API v3 para {len(targets_urls)} URL(s) y {len(targets_ips)} IP(s)...[/bold cyan]")

    for u in targets_urls:
        results.append(vt_lookup_url(u, api_key))

    for ip in targets_ips:
        results.append(vt_lookup_ip(ip, api_key))

    return results


def get_url_hostname(url: str) -> Optional[str]:
    """Devuelve el hostname normalizado de una URL HTTP(S) válida."""
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            return None
        return parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return None


def urlscan_submit_url(url: str, api_key: str) -> Dict[str, Any]:
    """Envía una URL a urlscan.io con visibilidad unlisted."""
    api_url = "https://urlscan.io/api/v1/scan/"
    payload = json.dumps({"url": url, "visibility": "unlisted"}).encode()
    req = urllib.request.Request(api_url, data=payload, headers={
        "API-Key": api_key,
        "Content-Type": "application/json",
        "User-Agent": "Email-Auth-Analyzer/1.0"
    })

    try:
        with urllib.request.urlopen(req, context=get_ssl_context(), timeout=20) as response:
            data = json.loads(response.read().decode())
            if not isinstance(data, dict):
                raise ValueError("Respuesta JSON inesperada de urlscan.")
            scan_id = data.get("uuid", "")
            if not isinstance(scan_id, str) or not scan_id:
                raise ValueError("urlscan no devolvió el identificador del escaneo.")
            return {
                "target": url,
                "provider": "urlscan",
                "status": "submitted",
                "visibility": "unlisted",
                "scan_id": scan_id,
                "result_url": data.get("result") or (
                    f"https://urlscan.io/result/{scan_id}/" if scan_id else ""
                ),
                "message": "Enviada a escaneo; el resultado puede tardar unos segundos."
            }
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            message = "API Key de urlscan inválida o sin autorización."
        elif e.code == 429:
            message = "Cuota de urlscan excedida (Rate Limit)."
        else:
            message = f"Error HTTP {e.code} de urlscan."
        return {"target": url, "provider": "urlscan", "status": "error", "message": message}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, UnicodeError) as e:
        return {
            "target": url,
            "provider": "urlscan",
            "status": "error",
            "message": f"No se pudo consultar urlscan: {e}"
        }


def urlscan_get_result(result: Dict[str, Any], api_key: str) -> Dict[str, Any]:
    """Recupera el resultado de un escaneo urlscan ya enviado."""
    scan_id = result["scan_id"]
    api_url = f"https://urlscan.io/api/v1/result/{urllib.parse.quote(scan_id, safe='')}/"
    req = urllib.request.Request(api_url, headers={
        "API-Key": api_key,
        "User-Agent": "Email-Auth-Analyzer/1.0"
    })

    try:
        with urllib.request.urlopen(req, context=get_ssl_context(), timeout=20) as response:
            data = json.loads(response.read().decode())
        if not isinstance(data, dict):
            raise ValueError("Respuesta JSON inesperada del resultado de urlscan.")

        page = data.get("page", {})
        verdicts = data.get("verdicts", {})
        overall = verdicts.get("overall", {}) if isinstance(verdicts, dict) else {}
        if not isinstance(page, dict):
            page = {}
        if not isinstance(overall, dict):
            overall = {}

        result.update({
            "status": "success",
            "page_url": page.get("url", ""),
            "page_domain": page.get("domain", ""),
            "page_title": page.get("title", ""),
            "page_status": page.get("status", ""),
            "malicious": overall.get("malicious"),
            "score": overall.get("score"),
            "brands": overall.get("brands", []),
            "message": "Resultado de urlscan disponible."
        })
        return result
    except urllib.error.HTTPError as e:
        if e.code == 404:
            result["message"] = "Escaneo en progreso; esperando resultado de urlscan."
            return result
        if e.code == 410:
            message = "urlscan eliminó el resultado de este escaneo."
        elif e.code in (401, 403):
            message = "API Key de urlscan inválida o sin autorización para consultar resultados."
        elif e.code == 429:
            message = "Cuota de urlscan excedida al consultar el resultado (Rate Limit)."
        else:
            message = f"Error HTTP {e.code} al consultar el resultado de urlscan."
        result.update({"status": "error", "message": message})
        return result
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, UnicodeError) as e:
        result.update({
            "status": "error",
            "message": f"No se pudo obtener el resultado de urlscan: {e}"
        })
        return result


def urlscan_wait_for_results(results: List[Dict[str, Any]], api_key: str) -> None:
    """Espera hasta 30 segundos por los resultados de escaneos urlscan."""
    pending = [result for result in results if result.get("status") == "submitted"]
    if not pending:
        return

    time.sleep(10)
    deadline = time.monotonic() + 20
    while pending:
        for result in pending[:]:
            urlscan_get_result(result, api_key)
            if result.get("status") != "submitted":
                pending.remove(result)
        remaining = deadline - time.monotonic()
        if pending and remaining > 0:
            time.sleep(min(2, remaining))
        elif pending:
            break

    for result in pending:
        result["message"] = "El escaneo sigue en progreso; consulta el informe de urlscan más tarde."


def crtsh_lookup_domain(domain: str) -> Dict[str, Any]:
    """Consulta en crt.sh los certificados conocidos para un dominio."""
    query = urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
    api_url = f"https://crt.sh/?{query}"
    req = urllib.request.Request(api_url, headers={
        "User-Agent": "Email-Auth-Analyzer/1.0"
    })

    try:
        with urllib.request.urlopen(req, context=get_ssl_context(), timeout=20) as response:
            data = json.loads(response.read().decode())
        if not isinstance(data, list):
            raise ValueError("Respuesta JSON inesperada de crt.sh.")
        names = []
        for certificate in data:
            if not isinstance(certificate, dict):
                raise ValueError("Registro de certificado inesperado de crt.sh.")
            name_value = certificate.get("name_value", "")
            if not isinstance(name_value, str):
                continue
            for name in name_value.splitlines():
                if name and name not in names:
                    names.append(name)
        return {
            "target": domain,
            "provider": "crt.sh",
            "status": "success",
            "certificate_count": len(data),
            "names": names[:5],
        }
    except urllib.error.HTTPError as e:
        return {
            "target": domain,
            "provider": "crt.sh",
            "status": "error",
            "message": f"Error HTTP {e.code} de crt.sh."
        }
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, UnicodeError) as e:
        return {
            "target": domain,
            "provider": "crt.sh",
            "status": "error",
            "message": f"No se pudo consultar crt.sh: {e}"
        }


def whois_lookup_domain(domain: str, api_key: str) -> Dict[str, Any]:
    """Consulta el WHOIS normalizado de un dominio en who.is."""
    api_url = f"https://api.who.is/v1/whois/{urllib.parse.quote(domain, safe='')}"
    req = urllib.request.Request(api_url, headers={
        "Authorization": f"Bearer {api_key}",
        "User-Agent": "Email-Auth-Analyzer/1.0"
    })

    try:
        with urllib.request.urlopen(req, context=get_ssl_context(), timeout=20) as response:
            data = json.loads(response.read().decode())
        if not isinstance(data, dict):
            raise ValueError("Respuesta JSON inesperada de who.is.")
        events = data.get("events", [])
        if not isinstance(events, list):
            raise ValueError("Campo de eventos inesperado en respuesta de who.is.")
        events = [event for event in events if isinstance(event, dict)]
        expiration = next(
            (event.get("event_date", "") for event in events
             if str(event.get("event_action", "")).lower() in ("expiration", "expiry")),
            ""
        )
        registration = next(
            (event.get("event_date", "") for event in events
             if str(event.get("event_action", "")).lower() in ("registration", "registration date")),
            ""
        )
        return {
            "target": domain,
            "provider": "WHOIS",
            "status": "success",
            "registrar": data.get("registrar", ""),
            "whois_server": data.get("whois_server", ""),
            "snapshot_time": data.get("snapshot_time", ""),
            "registration": registration,
            "expiration": expiration,
            "statuses": data.get("statuses", []),
        }
    except urllib.error.HTTPError as e:
        if e.code == 401:
            message = "API Key de who.is inválida o no autorizada."
        elif e.code == 403:
            message = "El plan de who.is no permite esta consulta."
        elif e.code == 429:
            message = "Cuota de who.is excedida (Rate Limit)."
        elif e.code == 404:
            message = "who.is no encontró datos para este dominio."
        else:
            message = f"Error HTTP {e.code} de who.is."
        return {"target": domain, "provider": "WHOIS", "status": "error", "message": message}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, UnicodeError) as e:
        return {
            "target": domain,
            "provider": "WHOIS",
            "status": "error",
            "message": f"No se pudo consultar who.is: {e}"
        }


def analyze_links_with_intel(
    data: Dict[str, Any],
    urlscan_api_key: Optional[str],
    whois_api_key: Optional[str],
) -> List[Dict[str, Any]]:
    """Analiza los enlaces HTTP(S) y sus dominios con urlscan, crt.sh y who.is."""
    urls = list(dict.fromkeys(
        url for url in data.get("links", []) if get_url_hostname(url)
    ))
    if not urls:
        return []

    results = []
    if urlscan_api_key:
        console.print(f"[bold cyan]🔍 Enviando {len(urls)} URL(s) a urlscan (visibilidad unlisted)...[/bold cyan]")
        for url in urls:
            results.append(urlscan_submit_url(url, urlscan_api_key))
        urlscan_wait_for_results(results, urlscan_api_key)
    else:
        for url in urls:
            results.append({
                "target": url,
                "provider": "urlscan",
                "status": "no_key",
                "message": "Omitido (sin URLSCAN_API_KEY)"
            })

    domains = []
    for url in urls:
        domain = get_url_hostname(url)
        if not domain:
            continue
        try:
            ipaddress.ip_address(domain)
        except ValueError:
            if domain and domain not in domains:
                domains.append(domain)

    for domain in domains:
        results.append(crtsh_lookup_domain(domain))
        if whois_api_key:
            results.append(whois_lookup_domain(domain, whois_api_key))
        else:
            results.append({
                "target": domain,
                "provider": "WHOIS",
                "status": "no_key",
                "message": "Omitido (sin WHOIS_API_KEY)"
            })

    return results


# ============================================================================
# MOTOR HEURÍSTICO DE EVALUACIÓN
# ============================================================================

def evaluate_email_security(data: Dict[str, Any], vt_results: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Motor heurístico avanzado de evaluación de amenazas de correo.
    Detecta Phishing, Spoofing, Homóglifos (Punycode), BEC y fallas de autenticación.
    Incorpora la reputación de VirusTotal sobre URLs e IPs.
    """
    score = 0
    reasons = []
    threat_types = []

    spf = data.get("spf_result", "none").lower()
    dkim = data.get("dkim_result", "none").lower()
    dmarc = data.get("dmarc_result", "none").lower()
    from_dom = data.get("from_domain", "").lower()
    reply_to_dom = data.get("reply_to_domain", "").lower()
    from_name = data.get("from_name", "")
    full_text = f"{data.get('subject', '')} {data.get('body', '')}".lower()

    # 1. Evaluación de SPF
    if spf == "pass":
        score -= 20
    elif spf == "fail":
        score += 35
        reasons.append("🔴 [bold]SPF FAIL:[/bold] La IP remitente no tiene autorización para enviar en nombre del dominio.")
    elif spf == "softfail":
        score += 25
        reasons.append("🟡 [bold]SPF SOFTFAIL:[/bold] El servidor remitente probablemente no está autorizado (política no estricta).")
    elif spf in ["none", "neutral"]:
        score += 15
        reasons.append("⚪ [bold]SPF NONE/NEUTRAL:[/bold] El dominio remitente no tiene o no aplica registro SPF válido.")

    # 2. Evaluación de DKIM
    if dkim == "pass":
        score -= 20
    elif dkim == "fail":
        score += 35
        reasons.append("🔴 [bold]DKIM FAIL:[/bold] La firma criptográfica del mensaje es inválida o el contenido fue alterado.")
    elif dkim in ["none", "neutral"]:
        score += 15
        reasons.append("⚪ [bold]DKIM NONE:[/bold] El correo carece de firma digital criptográfica.")

    # 3. Evaluación de DMARC
    if dmarc == "pass":
        score -= 25
    elif dmarc == "fail":
        score += 40
        reasons.append("🔴 [bold]DMARC FAIL:[/bold] Violación de la política DMARC (falla de alineación entre From y SPF/DKIM).")
        if spf == "pass" and dkim == "pass" and data.get("spf_domain") != from_dom:
            reasons.append(f"⚠️ [bold]Desalineación DMARC:[/bold] SPF/DKIM pertenecen a [cyan]{data.get('spf_domain')}[/cyan], pero el From visible es [cyan]{from_dom}[/cyan].")

    # 4. Detección de Ataque Homóglifo / Punycode (IDN Spoofing)
    is_punycode = "xn--" in from_dom or any("xn--" in link for link in data.get("links", []))
    has_cyrillic = any(ord(char) > 127 for char in from_name)
    if is_punycode or has_cyrillic:
        score += 50
        threat_types.append("Ataque Homóglifo / IDN Spoofing (Punycode)")
        reasons.append(f"🚨 [bold red]Ataque Homóglifo Detectado:[/bold red] Uso de dominio Punycode ([cyan]{from_dom}[/cyan]) o caracteres visuales engañosos para imitar otra entidad.")

    # 5. Detección de Inconsistencia Reply-To (Bait & Switch)
    if reply_to_dom and from_dom and reply_to_dom != from_dom:
        score += 30
        threat_types.append("Desvío de Respuestas (Reply-To Spoofing)")
        reasons.append(f"⚠️ [bold]Inconsistencia Reply-To:[/bold] Las respuestas irán a [bold magenta]{data.get('reply_to_email')}[/bold magenta] en lugar del dominio del remitente ({from_dom}).")

    # 6. Detección de Fraude del CEO / BEC (Business Email Compromise)
    is_executive_claimed = any(kw in from_name.lower() for kw in EXECUTIVE_KEYWORDS)
    is_financial_urgency = any(k in full_text for k in ["transferencia", "pago", "cbu", "confidencial", "reunion", "reunión", "no puedo hablar"])
    
    if is_executive_claimed and is_financial_urgency:
        score += 45
        threat_types.append("Fraude del CEO / BEC (Business Email Compromise)")
        reasons.append("🚨 [bold red]Posible Fraude del CEO (BEC):[/bold red] El remitente usa un nombre de jerarquía o gerencia solicitando transacciones confidenciales/urgentes fuera de canales normales.")

    # 7. Detección de Enlaces Sospechosos y Acortadores (bit.ly, etc.)
    suspicious_links = []
    for link in data.get("links", []):
        if any(shortener in link.lower() for shortener in ["bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl"]):
            suspicious_links.append(link)
    if suspicious_links:
        score += 25
        reasons.append(f"⚠️ [bold]Uso de enlaces acortados/ofuscados:[/bold] Se detectó enlace que oculta el destino real ([underline]{suspicious_links[0]}[/underline]).")

    # 8. Palabras clave de urgencia e ingeniería social
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_text]
    if found_keywords:
        kw_penalty = min(len(found_keywords) * 8, 25)
        score += kw_penalty
        unique_kws = list(set(found_keywords))[:5]
        reasons.append(f"⚠️ [bold]Patrón de Ingeniería Social:[/bold] Palabras de alarma o coacción detectadas ({', '.join(unique_kws)}).")

    # 9. Integración de Alertas de VirusTotal
    if vt_results:
        for vt in vt_results:
            if vt.get("status") == "success":
                mal = vt.get("malicious", 0)
                susp = vt.get("suspicious", 0)
                if mal > 0:
                    score += 50
                    threat_types.append(f"Detección Maliciosa en VirusTotal ({vt['type']})")
                    reasons.append(f"🚨 [bold red]VirusTotal Alerta ({vt['type']}):[/bold red] [cyan]{vt['target']}[/cyan] marcado como [bold red]MALICIOSO por {mal} motores[/bold red].")
                elif susp > 0:
                    score += 25
                    reasons.append(f"⚠️ [bold yellow]VirusTotal Sospecha ({vt['type']}):[/bold yellow] [cyan]{vt['target']}[/cyan] marcado como sospechoso por {susp} motores.")

    final_score = max(0, min(100, score))

    # Reglas críticas de seguridad (Override para ataques avanzados)
    if "Fraude del CEO / BEC (Business Email Compromise)" in threat_types:
        final_score = max(final_score, 85)
        reasons.insert(0, "⚠️ [bold yellow]Autenticación Engañosa:[/bold yellow] SPF/DKIM/DMARC están activos para el dominio del atacante, pero la identidad visible suplanta a directivos.")

    if is_punycode or has_cyrillic:
        final_score = max(final_score, 90)

    if final_score >= 60 or (spf == "fail" and dmarc == "fail") or is_punycode or "Fraude del CEO / BEC (Business Email Compromise)" in threat_types or any("Detección Maliciosa" in t for t in threat_types):
        verdict = "ALTO RIESGO - POSIBLE PHISHING / SUPLANTACIÓN"
        verdict_color = "bold white on red"
        badge_style = "red"
        status_icon = "🚨"
    elif final_score >= 35 or spf in ["fail", "softfail"] or dmarc == "fail":
        verdict = "RIESGO MEDIO - CORREO SOSPECHOSO"
        verdict_color = "bold black on yellow"
        badge_style = "yellow"
        status_icon = "⚠️"
    else:
        verdict = "BAJO RIESGO - CORREO LEGÍTIMO"
        verdict_color = "bold white on green"
        badge_style = "green"
        status_icon = "✅"

    return {
        "score": final_score,
        "verdict": verdict,
        "verdict_color": verdict_color,
        "badge_style": badge_style,
        "status_icon": status_icon,
        "reasons": reasons,
        "threat_types": list(dict.fromkeys(threat_types)),
    }


def format_badge(result_str: str) -> Text:
    """Genera insignias visuales para estados PASS, FAIL, SOFTFAIL, etc."""
    r = (result_str or "").lower().strip()
    if r == "pass":
        return Text(" ✔ PASS ", style="bold white on green")
    elif r == "fail":
        return Text(" ✖ FAIL ", style="bold white on red")
    elif r == "softfail":
        return Text(" ~ SOFTFAIL ", style="bold black on yellow")
    elif r in ["neutral", "none"]:
        return Text(f" ○ {r.upper()} ", style="bold white on dark_orange")
    else:
        return Text(f" ! {r.upper()} ", style="bold white on magenta")


def format_vt_badge(res: Dict[str, Any]) -> Text:
    """Genera insignias para los resultados de VirusTotal."""
    status = res.get("status")
    if status == "success":
        mal = res.get("malicious", 0)
        susp = res.get("suspicious", 0)
        harmless = res.get("harmless", 0)
        if mal > 0:
            return Text(f" ✖ {mal} MALICIOSO ", style="bold white on red")
        elif susp > 0:
            return Text(f" ! {susp} SOSPECHOSO ", style="bold black on yellow")
        else:
            return Text(f" ✔ LIMPIO ({harmless}) ", style="bold white on green")
    elif status == "submitted":
        return Text(" ⏳ EN COLA ", style="bold white on blue")
    elif status == "private":
        return Text(" 🏠 IP PRIVADA ", style="bold white on dark_blue")
    elif status == "not_found":
        return Text(" ? NO REGISTRADO ", style="dim white")
    elif status == "no_key":
        return Text(" ⚪ SIN API KEY ", style="dim white")
    else:
        return Text(" ⚠️ ERROR ", style="bold white on dark_red")


def format_intel_badge(res: Dict[str, Any]) -> Text:
    """Genera insignias para los análisis de URL y dominio."""
    status = res.get("status")
    if status == "success":
        if res.get("provider") == "urlscan" and res.get("malicious") is True:
            return Text(" ✖ MALICIOSO ", style="bold white on red")
        return Text(" ✔ CONSULTADO ", style="bold white on green")
    if status == "submitted":
        return Text(" ⏳ EN COLA ", style="bold white on blue")
    if status == "no_key":
        return Text(" ⚪ SIN API KEY ", style="dim white")
    return Text(" ⚠️ ERROR ", style="bold white on dark_red")


def render_eml_analysis(
    data: Dict[str, Any],
    vt_results: Optional[List[Dict[str, Any]]] = None,
    has_vt_key: bool = False,
    url_intel_results: Optional[List[Dict[str, Any]]] = None,
):
    """Muestra el reporte estilizado en terminal para un archivo EML."""
    eval_res = evaluate_email_security(data, vt_results)

    console.print()
    console.rule(f"[bold cyan]🔍 Análisis Forense de Correo: {data['file']}[/bold cyan]")

    # 1. Tabla de Metadatos del Mensaje
    meta_table = Table(box=box.ROUNDED, show_header=False, expand=True)
    meta_table.add_column("Campo", style="bold cyan", width=18)
    meta_table.add_column("Valor", style="white")

    meta_table.add_row("📁 Archivo EML", data["file"])
    meta_table.add_row("👤 Remitente (From)", data["from_raw"] or "N/A")
    if data["reply_to"]:
        mismatch_alert = " [bold red](⚠️ ¡No coincide con el remitente!)[/bold red]" if data["reply_to_domain"] != data["from_domain"] else ""
        meta_table.add_row("↩️ Responder a (Reply-To)", f"{data['reply_to']}{mismatch_alert}")
    meta_table.add_row("🎯 Destinatario (To)", data["to_raw"] or "N/A")
    meta_table.add_row("✉️ Asunto (Subject)", data["subject"] or "(Sin asunto)")
    if data["date"]:
        meta_table.add_row("📅 Fecha", data["date"])
    if data["source_ip"]:
        meta_table.add_row("🌐 IP de Origen", data["source_ip"])

    console.print(Panel(meta_table, title="[bold]📌 Metadatos y Cabeceras del Correo[/bold]", border_style="cyan"))

    # 2. Tabla de Protocolos de Autenticación
    auth_table = Table(box=box.ROUNDED, expand=True)
    auth_table.add_column("Protocolo", style="bold bright_white", width=12)
    auth_table.add_column("Resultado", justify="center", width=14)
    auth_table.add_column("Dominio Evaluado", style="white")
    auth_table.add_column("Evaluación Técnica", style="dim white")

    # SPF
    spf_res = data["spf_result"]
    spf_desc = (
        "IP emisora autorizada por el titular del dominio" if spf_res == "pass"
        else "IP emisora NO permitida en registro SPF" if spf_res == "fail"
        else "Permisivo: servidor no expresamente autorizado" if spf_res == "softfail"
        else "Sin política estricta de autorización SPF"
    )
    auth_table.add_row("SPF", format_badge(spf_res), data["spf_domain"] or "N/A", spf_desc)

    # DKIM
    dkim_res = data["dkim_result"]
    dkim_desc = (
        "Firma digital válida e íntegra" if dkim_res == "pass"
        else "Firma criptográfica inválida o alterada" if dkim_res == "fail"
        else "Mensaje sin firma digital DKIM"
    )
    auth_table.add_row("DKIM", format_badge(dkim_res), data["dkim_domain"] or "N/A", dkim_desc)

    # DMARC
    dmarc_res = data["dmarc_result"]
    dmarc_desc = (
        f"Alineación aprobada (p={data.get('dmarc_policy') or 'none'})" if dmarc_res == "pass"
        else f"Violación de política / desalineado (p={data.get('dmarc_policy') or 'none'})" if dmarc_res == "fail"
        else "Sin verificación DMARC"
    )
    auth_table.add_row("DMARC", format_badge(dmarc_res), data["dmarc_domain"] or data["from_domain"] or "N/A", dmarc_desc)

    console.print(Panel(auth_table, title="[bold]🛡️ Verificación de Autenticación (SPF / DKIM / DMARC)[/bold]", border_style="blue"))

    # 3. Tabla de VirusTotal (URLs e IPs detectadas)
    if vt_results:
        vt_table = Table(box=box.ROUNDED, expand=True)
        vt_table.add_column("Tipo", style="bold cyan", width=8, justify="center")
        vt_table.add_column("Indicador / Objetivo (IoC)", style="white", ratio=2)
        vt_table.add_column("Estado VirusTotal", justify="center", width=20)
        vt_table.add_column("Detalles / Reputación", style="dim white", ratio=2)

        for res in vt_results:
            target_str = res.get("target", "")
            if len(target_str) > 65:
                target_str = target_str[:62] + "..."

            status = res.get("status")
            if status == "success":
                if res.get("type") == "URL":
                    detalles = f"Rep: {res.get('reputation', 0)} | Categorías: {', '.join(res.get('categories', [])) or 'N/A'}"
                else:
                    detalles = f"País: {res.get('country', 'N/A')} | Org: {res.get('as_owner', 'N/A')} | Red: {res.get('network', 'N/A')}"
            else:
                detalles = res.get("message", "N/A")

            vt_table.add_row(res.get("type", "IoC"), target_str, format_vt_badge(res), detalles)

        vt_title = "[bold]🌐 Análisis de IoCs en VirusTotal API v3 (URLs e IPs)[/bold]"
        if not has_vt_key:
            vt_title += " [dim](Modo Pasivo: Sin API Key)[/dim]"
        console.print(Panel(vt_table, title=vt_title, border_style="magenta"))
    else:
        console.print(Panel("[dim]No se detectaron URLs ni IPs externas en el mensaje para analizar con VirusTotal.[/dim]", title="[bold]🌐 VirusTotal IoCs[/bold]", border_style="dim magenta"))

    # 4. Análisis de URLs y dominios con urlscan, crt.sh y WHOIS
    if url_intel_results:
        intel_table = Table(box=box.ROUNDED, expand=True)
        intel_table.add_column("Servicio", style="bold cyan", width=12)
        intel_table.add_column("URL / Dominio", style="white", ratio=2)
        intel_table.add_column("Estado", justify="center", width=18)
        intel_table.add_column("Detalles", style="dim white", ratio=3)

        for res in url_intel_results:
            target = res.get("target", "")
            if len(target) > 65:
                target = target[:62] + "..."
            if res.get("status") == "submitted":
                details = res.get("result_url") or res.get("message", "")
            elif res.get("status") == "success" and res.get("provider") == "urlscan":
                details = (
                    f"Detección maliciosa: {res.get('malicious') if res.get('malicious') is not None else 'N/D'} | "
                    f"Puntaje: {res.get('score') if res.get('score') is not None else 'N/D'} | "
                    f"Título: {res.get('page_title') or 'N/D'} | "
                    f"Marcas: {', '.join(res.get('brands', [])) or 'N/D'}"
                )
            elif res.get("status") == "success" and res.get("provider") == "crt.sh":
                names = ", ".join(res.get("names", [])) or "N/A"
                details = f"Certificados: {res.get('certificate_count', 0)} | Nombres: {names}"
            elif res.get("status") == "success" and res.get("provider") == "WHOIS":
                details = (
                    f"Registrador: {res.get('registrar') or 'N/A'} | "
                    f"Registro: {res.get('registration') or 'N/A'} | "
                    f"Vencimiento: {res.get('expiration') or 'N/A'}"
                )
            else:
                details = res.get("message", "Consulta completada.")
            intel_table.add_row(
                res.get("provider", "URL"),
                target,
                format_intel_badge(res),
                details,
            )

        console.print(Panel(
            intel_table,
            title="[bold]🔗 Análisis de URLs (urlscan, crt.sh y WHOIS)[/bold]",
            border_style="bright_blue"
        ))
    elif data.get("links"):
        console.print(Panel(
            "[dim]No se encontraron URLs HTTP(S) válidas para analizar.[/dim]",
            title="[bold]🔗 Análisis de URLs[/bold]",
            border_style="dim blue"
        ))

    # 5. Panel de Veredicto y Diagnóstico Anti-Phishing
    score = eval_res["score"]
    body_lines = []
    body_lines.append(f"\n {eval_res['status_icon']}  [bold]VEREDICTO:[/bold] [{eval_res['verdict_color']}]{eval_res['verdict']}[/]  |  Puntaje de Riesgo: [bold]{score}/100[/bold]\n")

    if eval_res["threat_types"]:
        body_lines.append("[bold red]Vectores de Ataque Identificados:[/bold red]")
        for tt in eval_res["threat_types"]:
            body_lines.append(f"  ⚡ [bold red]{tt}[/bold red]")
        body_lines.append("")

    reasons = eval_res["reasons"]
    if reasons:
        body_lines.append("[bold underline]Hallazgos de Seguridad:[/bold underline]")
        for r in reasons:
            body_lines.append(f"  • {r}")
    else:
        body_lines.append("  • [green]Todos los mecanismos de autenticación y alineación son legítimos.[/green]")

    body_lines.append("\n[bold underline]Recomendación para el Usuario:[/bold underline]")
    if score >= 60:
        body_lines.append("  🛑 [bold red]BLOQUEAR / ELIMINAR:[/bold red] Amenaza alta. No interactuar con enlaces, no responder y alertar al equipo de ciberseguridad.\n")
    elif score >= 35:
        body_lines.append("  ⚠️ [bold yellow]TRATAR CON PRECAUCIÓN:[/bold yellow] Presenta anomalías en remitente o autenticación. Confirmar por un canal externo verificado.\n")
    else:
        body_lines.append("  ✅ [bold green]CORREO AUTÉNTICO:[/bold green] Las firmas criptográficas y alineación de dominio concuerdan adecuadamente.\n")

    panel_content = Text.from_markup("\n".join(body_lines))
    console.print(Panel(panel_content, title="[bold]🎯 Diagnóstico Anti-Phishing[/bold]", border_style=eval_res["badge_style"]))


# def show_welcome_screen():
#     """Pantalla inicial interactiva."""
#     welcome_text = Text()
#     welcome_text.append("╔═══════════════════════════════════════════════════════════════╗\n", style="bold cyan")
#     welcome_text.append("║                      Analizador de correo                     ║\n", style="bold white")
#     welcome_text.append("╚═══════════════════════════════════════════════════════════════╝\n", style="bold cyan")

#     console.print()
#     console.print(Panel(
#         welcome_text,
#         border_style="bright_blue",
#         # padding=(1, 2)
#     ))


def prompt_for_eml_file() -> str:
    """Solicita al usuario interactivamente el archivo EML."""
    eml_files = sorted([f for f in os.listdir(".") if f.lower().endswith(".eml") and os.path.isfile(f)])

    if eml_files:
        table = Table(title="Correos EML disponibles en la carpeta actual:", box=box.ROUNDED, show_header=True)
        table.add_column("#", style="bold cyan", width=4, justify="center")
        table.add_column("Archivo EML", style="bold white")
        table.add_column("Tamaño", style="dim white", justify="right")

        for idx, filename in enumerate(eml_files, start=1):
            try:
                size_kb = os.path.getsize(filename) / 1024
                table.add_row(str(idx), filename, f"{size_kb:.1f} KB")
            except OSError:
                table.add_row(str(idx), filename, "N/A")


        console.print()
        console.print(Panel(
            table,
            title="Analizador de correo EML",
            border_style="bright_blue",
            padding=(1, 2)
        ))

    while True:
        try:
            choice = Prompt.ask("[bold cyan]➤ Ingrese la ruta, nombre o numero del archivo EML a analizar[/bold cyan] [dim](o 'q' para salir)[/dim]").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Operación cancelada.[/yellow]")
            sys.exit(0)

        if choice.lower() in ["q", "quit", "exit", "salir"]:
            console.print("[bold yellow]Saliendo del programa. ¡Hasta luego![/bold yellow]")
            sys.exit(0)

        if not choice:
            console.print("[red]⚠️ Por favor ingrese una ruta o número válido.[/red]")
            continue

        if choice.isdigit() and eml_files:
            num = int(choice)
            if 1 <= num <= len(eml_files):
                return eml_files[num - 1]
            else:
                console.print(f"[red]⚠️ Número fuera de rango (1 - {len(eml_files)}).[/red]")
                continue

        if os.path.isfile(choice):
            return choice

        if not choice.lower().endswith(".eml") and os.path.isfile(choice + ".eml"):
            return choice + ".eml"

        console.print(f"[bold red]❌ El archivo '{choice}' no fue encontrado.[/bold red] Inténtelo de nuevo.")


def resolve_virustotal_key(cli_key: Optional[str], is_interactive: bool = False) -> Optional[str]:
    """Obtiene la clave de VirusTotal desde CLI, variables de entorno o consulta interactiva."""
    if cli_key:
        return cli_key.strip()
    
    env_key = os.environ.get("VIRUSTOTAL_API_KEY") or os.environ.get("VT_API_KEY")
    if env_key:
        return env_key.strip()

    # Solo consultar interactivamente si el usuario no especificó el archivo por argumento
    if is_interactive and sys.stdin.isatty():
        console.print("[dim]💡 Para analizar las URLs e IPs con VirusTotal en tiempo real se requiere una API Key.[/dim]")
        try:
            key = Prompt.ask(
                "[cyan]➤ Ingrese su API Key de VirusTotal[/cyan] [dim](Enter para omitir)[/dim]",
                default=""
            ).strip()
            return key if key else None
        except (KeyboardInterrupt, EOFError):
            return None

    return None


def main():
    parser = argparse.ArgumentParser(
        description="Analizador Forense de Correo EML (SPF, DKIM, DMARC, Phishing y análisis de URLs).",
        epilog="Ejemplo: python analizador.py caso_grupo_1_paqueteria.eml"
    )
    parser.add_argument("archivo_eml", nargs="?", default=None, help="Ruta al archivo EML (opcional)")
    parser.add_argument("--vt-key", "--api-key", dest="vt_key", default=None, help="API Key de VirusTotal (o usar variable VIRUSTOTAL_API_KEY)")
    args = parser.parse_args()

    # show_welcome_screen()

    is_interactive = (args.archivo_eml is None)
    target_file = args.archivo_eml
    if not target_file:
        target_file = prompt_for_eml_file()
    else:
        if not os.path.isfile(target_file):
            console.print(f"[bold yellow]⚠️ El archivo especificado '{target_file}' no existe.[/bold yellow]")
            target_file = prompt_for_eml_file()
            is_interactive = True

    # Las claves se cargan desde .env o desde el entorno del proceso.
    vt_key = resolve_virustotal_key(args.vt_key, is_interactive=is_interactive)
    has_vt_key = bool(vt_key)
    urlscan_key = os.environ.get("URLSCAN_API_KEY", "").strip() or None
    whois_key = os.environ.get("WHOIS_API_KEY", "").strip() or None

    console.print(f"\n[bold green]⚙️  Procesando correo:[/bold green] [cyan]{target_file}[/cyan]...")
    try:
        data = parse_eml_file(target_file)
        
        # Consultar IoCs en VirusTotal
        vt_results = analyze_iocs_with_virustotal(data, vt_key)
        url_intel_results = analyze_links_with_intel(data, urlscan_key, whois_key)

        render_eml_analysis(
            data,
            vt_results,
            has_vt_key=has_vt_key,
            url_intel_results=url_intel_results,
        )
        
        if not has_vt_key and (data.get("links") or data.get("detected_ips")):
            console.print("[dim yellow]💡 Tip: Configura tu API Key mediante export VIRUSTOTAL_API_KEY='tu_clave' o con --vt-key para ver detecciones de antivirus en tiempo real.[/dim yellow]")

        console.print(f"\n[dim green]✔ Análisis completado exitosamente.[/dim green]\n")
    except Exception as e:
        console.print(f"[bold red]❌ Error al procesar el archivo EML:[/bold red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
