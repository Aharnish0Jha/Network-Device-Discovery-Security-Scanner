import subprocess
import shutil
import os
import xml.etree.ElementTree as ET
import re
import ipaddress
from typing import Dict, List, Optional, Tuple
import socket
import concurrent.futures
import time


def _run_command(command: List[str]) -> Tuple[int, str, str]:
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        return process.returncode, stdout, stderr
    except FileNotFoundError as e:
        return 127, "", str(e)


def locate_nmap_executable() -> Optional[str]:
    # Prefer PATH
    nmap_path = shutil.which("nmap")
    if nmap_path:
        return nmap_path
    # Common Windows install paths
    candidates = [
        r"C:\\Program Files\\Nmap\\nmap.exe",
        r"C:\\Program Files (x86)\\Nmap\\nmap.exe",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


def is_nmap_available() -> bool:
    exe = locate_nmap_executable()
    if not exe:
        return False
    code, _, _ = _run_command([exe, "-V"])  # Prints version
    return code == 0


def detect_local_cidr_windows() -> Optional[str]:
    # Try PowerShell first for better interface detection
    try:
        code, stdout, _ = _run_command([
            "powershell", "-Command", 
            "Get-NetIPConfiguration | Where-Object {$_.IPv4Address -and $_.NetAdapter.Status -eq 'Up'} | Select-Object -First 1 | ForEach-Object {$_.IPv4Address.IPAddress + '/' + $_.IPv4Address.PrefixLength}"
        ])
        if code == 0 and stdout.strip():
            cidr = stdout.strip()
            # Validate the CIDR format
            try:
                ipaddress.IPv4Network(cidr, strict=False)
                return cidr
            except Exception:
                pass
    except Exception:
        pass

    # Fallback to ipconfig parsing
    code, stdout, _ = _run_command(["ipconfig"])
    if code != 0:
        return None

    # Find IPv4 and Subnet Mask pairs from the active adapters
    ipv4_pattern = re.compile(r"IPv4 Address.*?:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)")
    mask_pattern = re.compile(r"Subnet Mask.*?:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)")

    lines = stdout.splitlines()
    ipv4: Optional[str] = None
    mask: Optional[str] = None
    candidates: List[Tuple[str, str]] = []

    for line in lines:
        ipv4_match = ipv4_pattern.search(line)
        if ipv4_match:
            ipv4 = ipv4_match.group(1)
            continue
        mask_match = mask_pattern.search(line)
        if mask_match and ipv4:
            mask = mask_match.group(1)
            candidates.append((ipv4, mask))
            ipv4, mask = None, None

    def to_cidr(ip_str: str, mask_str: str) -> Optional[str]:
        try:
            network = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
            return str(network)
        except Exception:
            return None

    # Prefer private ranges, especially Wi-Fi networks (typically 192.168.x.x)
    private_candidates = []
    wifi_candidates = []
    
    for ip_str, mask_str in candidates:
        cidr = to_cidr(ip_str, mask_str)
        if not cidr:
            continue
        if ipaddress.ip_address(ip_str).is_private:
            private_candidates.append(cidr)
            # Prefer Wi-Fi networks (192.168.x.x) over VirtualBox networks (192.168.56.x)
            if ip_str.startswith("192.168.") and not ip_str.startswith("192.168.56."):
                wifi_candidates.append(cidr)

    # Return Wi-Fi network first, then other private networks
    if wifi_candidates:
        return wifi_candidates[0]
    
    if private_candidates:
        # Prefer /24 if available, else return first
        for cidr in private_candidates:
            if cidr.endswith("/24"):
                return cidr
        return private_candidates[0]

    # Fallback to any candidate
    for ip_str, mask_str in candidates:
        cidr = to_cidr(ip_str, mask_str)
        if cidr:
            return cidr

    return None


def nmap_discover_hosts(target_cidr: str) -> str:
    # Host discovery (no port scan)
    # -sn: Ping scan, -oX - outputs XML to stdout
    exe = locate_nmap_executable()
    if not exe:
        raise RuntimeError("Nmap executable not found. Please install Nmap and ensure it is in PATH.")
    code, stdout, stderr = _run_command([exe, "-sn", target_cidr, "-oX", "-"])
    if code != 0:
        raise RuntimeError(f"nmap discovery failed: {stderr.strip()}")
    return stdout


def nmap_aggressive_scan(target: str) -> str:
    # Aggressive scan: service/version detection, OS detection, traceroute, scripts
    # -A implies -O -sV -sC --traceroute; -T4 for speed; -oX - outputs XML
    exe = locate_nmap_executable()
    if not exe:
        raise RuntimeError("Nmap executable not found. Please install Nmap and ensure it is in PATH.")
    code, stdout, stderr = _run_command([exe, "-A", "-T4", target, "-oX", "-"])
    if code != 0:
        raise RuntimeError(f"nmap aggressive scan failed: {stderr.strip()}")
    return stdout


def parse_nmap_xml(xml_text: str) -> List[Dict]:
    # Returns list of hosts with fields: ip, hostname, mac, vendor, status, ports: List[...]
    hosts: List[Dict] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return hosts

    for host in root.findall("host"):
        status = host.find("status")
        state = status.get("state") if status is not None else "unknown"
        if state not in {"up", "unknown"}:
            continue

        addresses = host.findall("address")
        ip = None
        mac = None
        vendor = None
        for addr in addresses:
            addrtype = addr.get("addrtype")
            if addrtype == "ipv4":
                ip = addr.get("addr")
            elif addrtype == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor")

        hostname_node = host.find("hostnames/hostname")
        hostname = hostname_node.get("name") if hostname_node is not None else None

        ports_info: List[Dict] = []
        ports_node = host.find("ports")
        if ports_node is not None:
            for port in ports_node.findall("port"):
                portid = port.get("portid")
                protocol = port.get("protocol")
                state_node = port.find("state")
                state_val = state_node.get("state") if state_node is not None else None
                service_node = port.find("service")
                service_name = service_node.get("name") if service_node is not None else None
                product = service_node.get("product") if service_node is not None else None
                version = service_node.get("version") if service_node is not None else None
                extrainfo = service_node.get("extrainfo") if service_node is not None else None
                ports_info.append({
                    "port": int(portid) if portid else None,
                    "protocol": protocol,
                    "state": state_val,
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "extra": extrainfo,
                })

        os_match = None
        os_node = host.find("os")
        if os_node is not None:
            match = os_node.find("osmatch")
            if match is not None:
                os_match = match.get("name")

        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "mac": mac,
            "vendor": vendor,
            "status": state,
            "os": os_match,
            "ports": sorted(ports_info, key=lambda p: (p["protocol"] or "", p["port"] or 0)),
        })

    return hosts


# --------------------- Fallback (no Nmap) ---------------------

COMMON_PORTS: List[int] = [
    20, 21, 22, 23, 25, 53, 80, 110, 139, 143, 389, 443, 445, 465, 587,
    631, 993, 995, 1433, 1521, 2049, 3000, 3306, 3389, 5000, 5432, 5672,
    5900, 6379, 8080, 8443, 9000
]


def _ping_host_windows(ip: str, timeout_ms: int = 400) -> bool:
    code, _, _ = _run_command(["ping", "-n", "1", "-w", str(timeout_ms), ip])
    return code == 0


def _tcp_connect(ip: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def _cidr_to_hosts(cidr: str) -> List[str]:
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
        return [str(ip) for ip in net.hosts()]
    except Exception:
        return []


def fallback_discover_hosts(cidr: str, max_workers: int = 128, ping_timeout_ms: int = 400, progress_callback=None) -> List[Dict]:
    hosts: List[str] = _cidr_to_hosts(cidr)
    results: List[Dict] = []
    if not hosts:
        return results

    total_hosts = len(hosts)
    if progress_callback:
        progress_callback(0, total_hosts, "Starting discovery...")

    def check(ip: str) -> Optional[str]:
        if _ping_host_windows(ip, timeout_ms=ping_timeout_ms):
            return ip
        # As a fallback, try a quick TCP connect on port 80 which may also imply host is up
        if _tcp_connect(ip, 80):
            return ip
        return None

    completed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(check, ip): ip for ip in hosts}
        for future in concurrent.futures.as_completed(future_to_ip):
            completed += 1
            if progress_callback:
                progress_callback(completed, total_hosts, f"Checked {completed}/{total_hosts} hosts...")
            ip = future_to_ip[future]
            result = future.result()
            if result:
                results.append({
                    "ip": result,
                    "hostname": None,
                    "mac": None,
                    "vendor": None,
                    "status": "up",
                    "os": None,
                    "ports": [],
                })
    if progress_callback:
        progress_callback(total_hosts, total_hosts, "Discovery complete!")
    return results


def fallback_scan_host(ip: str, ports: Optional[List[int]] = None, timeout: float = 0.4, max_workers: int = 128) -> Dict:
    ports_to_scan = ports or COMMON_PORTS
    open_ports: List[Dict] = []

    def check_port(p: int) -> Optional[int]:
        return p if _tcp_connect(ip, p, timeout=timeout) else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for p in executor.map(check_port, ports_to_scan):
            if p is not None:
                open_ports.append({
                    "port": p,
                    "protocol": "tcp",
                    "state": "open",
                    "service": None,
                    "product": None,
                    "version": None,
                    "extra": None,
                })

    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        hostname = None

    return {
        "ip": ip,
        "hostname": hostname,
        "mac": None,
        "vendor": None,
        "status": "up",
        "os": None,
        "ports": sorted(open_ports, key=lambda p: p["port"]),
    }


# --------------------- Public API (auto-select engine) ---------------------

def discover_devices(target_cidr: str, ping_timeout_ms: int = 400, max_workers: int = 128, progress_callback=None) -> List[Dict]:
    if is_nmap_available():
        xml = nmap_discover_hosts(target_cidr)
        return parse_nmap_xml(xml)
    return fallback_discover_hosts(target_cidr, max_workers=max_workers, ping_timeout_ms=ping_timeout_ms, progress_callback=progress_callback)


def scan_host_details(target_ip: str, ports: Optional[List[int]] = None, tcp_timeout: float = 0.4, max_workers: int = 128) -> Dict:
    if is_nmap_available():
        xml = nmap_aggressive_scan(target_ip)
        hosts = parse_nmap_xml(xml)
        return hosts[0] if hosts else {"ip": target_ip, "ports": []}
    return fallback_scan_host(target_ip, ports=ports, timeout=tcp_timeout, max_workers=max_workers)

