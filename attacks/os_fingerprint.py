import time
from scapy.all import Ether, IP, TCP, ARP, srp, get_if_hwaddr, RandShort
from attacks.base import BaseAttack


class OsFingerprint(BaseAttack):
    def run(self):
        target_ip = self.params.get("target_ip", "")
        port      = int(self.params.get("target_port", 80))

        if not target_ip:
            self.log("OS Fingerprint: no target IP", "error"); return

        arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
        ans, _  = srp(arp_pkt, iface=self.iface, timeout=2, verbose=False)
        dst_mac = ans[0][1][ARP].hwsrc if ans else "ff:ff:ff:ff:ff:ff"
        src_mac = get_if_hwaddr(self.iface)
        writer  = self.open_pcap()

        probes = [
            ("NULL",    0x000, "No flags — RFC non-compliant"),
            ("FIN",     0x001, "FIN without ACK"),
            ("XMAS",    0x029, "FIN+URG+PSH Christmas tree"),
            ("SYN+FIN", 0x003, "Illegal SYN+FIN"),
            ("ACK",     0x010, "Unsolicited ACK"),
            ("SYN",     0x002, "Standard SYN baseline"),
        ]

        self.log(f"OS Fingerprint → {target_ip}:{port} ({len(probes)} probes)", "warn")

        for name, flags, desc in probes:
            if self._stop.is_set(): break
            pkt = (
                Ether(src=src_mac, dst=dst_mac)
                / IP(dst=target_ip)
                / TCP(dport=port, flags=flags, sport=RandShort())
            )
            self.write(pkt)
            ans2, _ = srp(pkt, iface=self.iface, timeout=1.5, verbose=False)
            if ans2:
                rcv = ans2[0][1]
                if rcv.haslayer(TCP):
                    ttl = rcv[IP].ttl
                    fl  = rcv[TCP].flags
                    self.write(rcv)
                    if ttl <= 64:
                        hint = "Linux / macOS / Android"
                    elif ttl <= 128:
                        hint = "Windows"
                    else:
                        hint = "Cisco / Network device"
                    self.log(
                        f"  {name:<10} ({desc}) → flags=0x{fl:03x} ttl={ttl} | {hint}",
                        "success"
                    )
            else:
                self.log(f"  {name:<10} ({desc}) → no response", "info")
            time.sleep(0.3)

        writer.close()
        self.log("OS Fingerprint complete", "success")
