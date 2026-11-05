from scapy.all import ARP, sniff
from attacks.base import BaseAttack


class ArpPoisonDetect(BaseAttack):
    def run(self):
        writer  = self.open_pcap()
        ip_mac  = {}
        self.log(f"ARP Poison Detector: listening on {self.iface} …", "info")

        def handle(pkt):
            if not pkt.haslayer(ARP) or pkt[ARP].op != 2:
                return
            ip  = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            self.write(pkt)

            if ip not in ip_mac:
                ip_mac[ip] = set()
                ip_mac[ip].add(mac)
                self.log(f"  ARP: {ip} → {mac}", "info")
            else:
                ip_mac[ip].add(mac)
                if len(ip_mac[ip]) > 1:
                    self.log(
                        f"🚨 CONFLICT: {ip} claimed by {len(ip_mac[ip])} MACs: "
                        f"{', '.join(ip_mac[ip])}", "error"
                    )

        sniff(
            iface=self.iface,
            filter="arp",
            prn=handle,
            store=False,
            stop_filter=lambda _: self._stop.is_set(),
        )
        writer.close()
        self.log("ARP Poison Detector: stopped", "info")
