"""
hping3 Random Source Traffic Generator  — hping3 --rand-source
Sends TCP/UDP/ICMP packets with a fully randomised source IP per packet.
Generates the traffic pattern an analyst would see from a spoofed-source
flood or reconnaissance sweep — without flooding rates (configurable delay).
Purpose: SOC training capture, IDS rule tuning, filter validation.
"""
import time, random, threading
from scapy.all import (Ether, IP, TCP, UDP, ICMP, ARP,
                        srp, sendp, get_if_hwaddr, RandShort)
from attacks.base import BaseAttack


class Hping3RandSource(BaseAttack):
    def run(self):
        target_ip   = self.params.get("target_ip", "")
        target_port = int(self.params.get("target_port", 80))
        proto       = self.params.get("proto", "tcp").lower()
        flags_str   = self.params.get("flags", "S")
        count       = int(self.params.get("count", 500))
        interval    = float(self.params.get("interval", 0.05))
        threads_n   = int(self.params.get("threads", 2))

        if not target_ip:
            self.log("hping3 RandSource: no target IP", "error"); return

        arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
        ans, _  = srp(arp_pkt, iface=self.iface, timeout=2, verbose=False)
        dst_mac = ans[0][1][ARP].hwsrc if ans else "ff:ff:ff:ff:ff:ff"
        src_mac = get_if_hwaddr(self.iface)
        writer  = self.open_pcap()
        counters = {"sent": 0}
        lock     = threading.Lock()

        self.log(
            f"hping3 RandSource → {target_ip}:{target_port}  "
            f"proto={proto}  count={count}  {threads_n} threads",
            "warn"
        )

        def rand_ip():
            return (f"{random.randint(1,223)}.{random.randint(0,254)}."
                    f"{random.randint(0,254)}.{random.randint(1,254)}")

        def sender():
            while not self._stop.is_set():
                with lock:
                    if count and counters["sent"] >= count:
                        self._stop.set(); break
                src = rand_ip()
                if proto == "tcp":
                    pkt = (Ether(src=src_mac, dst=dst_mac)
                           / IP(src=src, dst=target_ip, ttl=random.randint(32,128))
                           / TCP(sport=RandShort(), dport=target_port,
                                 flags=flags_str, seq=random.randint(0, 0xFFFFFFFF)))
                elif proto == "udp":
                    pkt = (Ether(src=src_mac, dst=dst_mac)
                           / IP(src=src, dst=target_ip, ttl=random.randint(32,128))
                           / UDP(sport=RandShort(), dport=target_port)
                           / bytes(random.getrandbits(8) for _ in range(32)))
                else:
                    pkt = (Ether(src=src_mac, dst=dst_mac)
                           / IP(src=src, dst=target_ip, ttl=random.randint(32,128))
                           / ICMP(type=8, code=0, id=random.randint(0,0xFFFF)))

                try:
                    sendp(pkt, iface=self.iface, verbose=False)
                    with lock:
                        self.write(pkt)
                        counters["sent"] += 1
                        n = counters["sent"]
                    if n % 100 == 0:
                        self.log(f"  RandSource: {n}/{count} packets sent", "info")
                except Exception as e:
                    self.log(f"hping3 RandSource error: {e}", "error"); break
                time.sleep(interval)

        workers = [threading.Thread(target=sender, daemon=True) for _ in range(threads_n)]
        for w in workers: w.start()
        for w in workers: w.join()
        writer.close()
        self.log(f"hping3 RandSource done — {counters['sent']} packets sent", "success")
