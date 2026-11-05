from scapy.all import Ether, IP, ICMP, srp
from attacks.base import BaseAttack
from ipaddress import IPv4Network
from queue import Queue, Empty
import threading


class IcmpSweep(BaseAttack):
    def run(self):
        subnet = self.params.get("subnet", "")
        if not subnet:
            from scapy.all import get_if_addr
            ip    = get_if_addr(self.iface)
            parts = ip.split(".")
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

        hosts  = [str(h) for h in IPv4Network(subnet, strict=False).hosts()]
        writer = self.open_pcap()
        alive  = []
        queue  = Queue()
        for h in hosts: queue.put(h)

        self.log(f"ICMP Sweep: scanning {len(hosts)} hosts on {subnet}", "info")

        def worker():
            while not self._stop.is_set():
                try:
                    target = queue.get_nowait()
                except Empty:
                    break
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst=target, ttl=64) / ICMP(type=8, code=0)
                try:
                    ans, _ = srp(pkt, iface=self.iface, timeout=0.5, verbose=False)
                    self.write(pkt)
                    for _, rcv in ans:
                        if rcv.haslayer(ICMP):
                            ttl = rcv[IP].ttl
                            src = rcv[IP].src
                            alive.append(src)
                            self.write(rcv)
                            hint = "Linux/macOS" if ttl <= 64 else ("Windows" if ttl <= 128 else "Network device")
                            self.log(f"  ALIVE {src:<18} TTL={ttl} ({hint})", "success")
                except Exception:
                    pass
                finally:
                    queue.task_done()

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(50)]
        for t in threads: t.start()
        for t in threads: t.join()
        writer.close()
        self.log(f"ICMP Sweep done — {len(alive)} host(s) alive", "success")
