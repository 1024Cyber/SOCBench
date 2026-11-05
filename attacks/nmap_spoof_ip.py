"""
Nmap Spoof-IP Scan  — -S <spoofed_ip>
Sends SYN probes with a forged source IP address.
Responses go to the spoofed IP, not the scanner — combine with
a decoy or sniff responses on the wire (tshark/Wireshark).
Produces realistic spoofed-source recon traffic for SOC training.
"""
import threading
from queue import Queue, Empty
from scapy.all import Ether, IP, TCP, ARP, srp, sendp, get_if_hwaddr, RandShort
from attacks.base import BaseAttack


class NmapSpoofIp(BaseAttack):
    def run(self):
        target_ip  = self.params.get("target_ip", "")
        spoof_ip   = self.params.get("spoof_ip", "")
        port_range = self.params.get("port_range", "1-1024")

        if not target_ip:
            self.log("Spoof-IP Scan: no target IP", "error"); return
        if not spoof_ip:
            import random
            spoof_ip = (f"{random.randint(1,223)}.{random.randint(0,254)}."
                        f"{random.randint(0,254)}.{random.randint(1,254)}")
            self.log(f"No spoof IP provided — using random: {spoof_ip}", "warn")

        self.log(f"Spoof-IP Scan → {target_ip}  src={spoof_ip}", "warn")
        self.log("  Note: responses go to spoof IP — capture locally in Wireshark", "info")

        try:
            p_start, p_end = (int(x) for x in port_range.split("-"))
        except ValueError:
            self.log("Invalid port range", "error"); return

        arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
        ans, _  = srp(arp_pkt, iface=self.iface, timeout=2, verbose=False)
        dst_mac = ans[0][1][ARP].hwsrc if ans else "ff:ff:ff:ff:ff:ff"
        src_mac = get_if_hwaddr(self.iface)
        writer  = self.open_pcap()
        q = Queue()
        for p in range(p_start, p_end + 1): q.put(p)

        def worker():
            while not self._stop.is_set():
                try: port = q.get_nowait()
                except Empty: break
                pkt = (Ether(src=src_mac, dst=dst_mac)
                       / IP(src=spoof_ip, dst=target_ip)
                       / TCP(dport=port, flags="S", sport=RandShort()))
                sendp(pkt, iface=self.iface, verbose=False)
                self.write(pkt)
                q.task_done()

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(50)]
        for t in threads: t.start()
        for t in threads: t.join()
        writer.close()
        self.log(f"Spoof-IP scan done — {p_end - p_start + 1} probes sent from {spoof_ip}", "success")
