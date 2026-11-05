import random, time
from scapy.all import Ether, IP, TCP, sendp, get_if_hwaddr, get_if_addr, RandShort
from attacks.base import BaseAttack


class C2Beacon(BaseAttack):
    def run(self):
        target_ip = self.params.get("target_ip", "")
        c2_port   = int(self.params.get("target_port", 443))
        interval  = float(self.params.get("interval", 30))
        jitter    = float(self.params.get("jitter", 3))

        if not target_ip:
            self.log("C2 Beacon: no target IP", "error"); return

        dst_mac = self.resolve_mac(target_ip)
        src_mac = get_if_hwaddr(self.iface)
        src_ip  = get_if_addr(self.iface)
        writer  = self.open_pcap()
        count   = 0

        self.log(f"C2 Beacon → {target_ip}:{c2_port} every ~{interval}s (±{jitter}s)", "warn")

        while not self._stop.is_set():
            sport = random.randint(49152, 65535)
            seq   = random.randint(0, 0xFFFFFFFF)
            payload = bytes(random.randint(0x20, 0x7E) for _ in range(random.randint(32, 128)))

            for pkt in [
                Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=target_ip) / TCP(sport=sport, dport=c2_port, flags="S", seq=seq),
                Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=target_ip) / TCP(sport=sport, dport=c2_port, flags="PA", seq=seq+1, ack=1) / payload,
                Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=target_ip) / TCP(sport=sport, dport=c2_port, flags="FA", seq=seq+1+len(payload), ack=1),
            ]:
                sendp(pkt, iface=self.iface, verbose=False)
                self.write(pkt)

            count += 1
            self.log(f"C2 Beacon #{count} sent to {target_ip}:{c2_port}", "info")

            sleep_t = max(0.5, interval + random.uniform(-jitter, jitter))
            for _ in range(int(sleep_t * 10)):
                if self._stop.is_set(): break
                time.sleep(0.1)

        writer.close()
