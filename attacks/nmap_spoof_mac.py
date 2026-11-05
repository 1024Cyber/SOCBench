"""
Nmap Spoof MAC Scan  — --spoof-mac <vendor|MAC|0>
Sends SYN probes with a forged Ethernet source MAC address.
Useful for bypassing MAC-based ACLs and generating interesting L2 traffic.
0 = random MAC, vendor string = OUI lookup, full MAC = exact spoof.
"""
import random, threading
from queue import Queue, Empty
from scapy.all import Ether, IP, TCP, ARP, srp, sendp, get_if_hwaddr, RandShort
from attacks.base import BaseAttack

# Known OUI prefixes for vendor spoofing
VENDOR_OUIS = {
    "apple":  [0x00, 0x17, 0xf2],
    "cisco":  [0x00, 0x1a, 0xa1],
    "dell":   [0x00, 0x14, 0x22],
    "hp":     [0x3c, 0xd9, 0x2b],
    "intel":  [0x8c, 0xec, 0x4b],
    "samsung":[0x8c, 0x71, 0xf8],
}


def build_spoof_mac(spoof_arg: str) -> str:
    arg = spoof_arg.strip().lower()
    if arg == "0" or arg == "random":
        octets = [random.randint(0, 255) for _ in range(6)]
        octets[0] = (octets[0] & 0xFE) | 0x02
        return ":".join(f"{b:02x}" for b in octets)
    # Full MAC
    if len(arg.replace(":", "").replace("-", "")) == 12:
        return arg.replace("-", ":")
    # Vendor prefix
    for vendor, oui in VENDOR_OUIS.items():
        if vendor in arg:
            tail = [random.randint(0, 255) for _ in range(3)]
            return ":".join(f"{b:02x}" for b in oui + tail)
    # Fallback random
    octets = [random.randint(0, 255) for _ in range(6)]
    octets[0] = (octets[0] & 0xFE) | 0x02
    return ":".join(f"{b:02x}" for b in octets)


class NmapSpoofMac(BaseAttack):
    def run(self):
        target_ip  = self.params.get("target_ip", "")
        port_range = self.params.get("port_range", "1-1024")
        spoof_arg  = self.params.get("spoof_mac", "0")

        if not target_ip:
            self.log("Spoof-MAC Scan: no target IP", "error"); return

        spoof_mac = build_spoof_mac(spoof_arg)
        self.log(f"Spoof-MAC Scan → {target_ip}  using MAC: {spoof_mac}", "warn")

        try:
            p_start, p_end = (int(x) for x in port_range.split("-"))
        except ValueError:
            self.log("Invalid port range", "error"); return

        arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
        ans, _  = srp(arp_pkt, iface=self.iface, timeout=2, verbose=False)
        dst_mac = ans[0][1][ARP].hwsrc if ans else "ff:ff:ff:ff:ff:ff"
        writer  = self.open_pcap()
        open_ports = []
        q = Queue()
        for p in range(p_start, p_end + 1): q.put(p)

        def worker():
            while not self._stop.is_set():
                try: port = q.get_nowait()
                except Empty: break
                pkt = (Ether(src=spoof_mac, dst=dst_mac)
                       / IP(dst=target_ip)
                       / TCP(dport=port, flags="S", sport=RandShort()))
                self.write(pkt)
                ans2, _ = srp(pkt, iface=self.iface, timeout=0.5, verbose=False)
                for _, rcv in ans2:
                    if rcv.haslayer(TCP) and (rcv[TCP].flags & 0x12):
                        open_ports.append(port)
                        self.log(f"  OPEN  {target_ip}:{port}", "success")
                q.task_done()

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(50)]
        for t in threads: t.start()
        for t in threads: t.join()
        writer.close()
        self.log(f"Spoof-MAC scan done — spoofed MAC: {spoof_mac} — {len(open_ports)} open port(s)", "success")
