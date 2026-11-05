"""Deep network scanner — ARP + ICMP, returns list of {ip, mac, hostname}."""
import socket
from scapy.all import Ether, ARP, IP, ICMP, srp, conf


class NetworkScanner:
    def __init__(self, iface: str):
        self.iface = iface
        conf.iface = iface
        conf.verb  = 0

    def _get_subnet(self) -> str:
        from scapy.all import get_if_addr
        ip = get_if_addr(self.iface)
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    def _reverse_dns(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""

    def scan(self) -> list:
        subnet = self._get_subnet()
        results = []

        # Pass 1: ARP sweep
        arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        ans, _  = srp(arp_pkt, iface=self.iface, timeout=2, verbose=False)
        arp_found = {}
        for _, rcv in ans:
            ip  = rcv[ARP].psrc
            mac = rcv[ARP].hwsrc
            arp_found[ip] = mac

        # Pass 2: ICMP sweep for hosts that didn't respond to ARP
        from ipaddress import IPv4Network
        all_hosts = [str(h) for h in IPv4Network(subnet, strict=False).hosts()]
        icmp_targets = [h for h in all_hosts if h not in arp_found]

        if icmp_targets:
            pkts = [Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst=h) / ICMP() for h in icmp_targets]
            for pkt in pkts:
                ans2, _ = srp(pkt, iface=self.iface, timeout=0.5, verbose=False)
                for _, rcv in ans2:
                    if rcv.haslayer(ICMP) and rcv[ICMP].type == 0:
                        ip = rcv[IP].src
                        if ip not in arp_found:
                            arp_found[ip] = rcv.src  # use Ether src as MAC

        # Build result list
        for ip, mac in arp_found.items():
            hostname = self._reverse_dns(ip)
            results.append({"ip": ip, "mac": mac, "hostname": hostname})

        return results
