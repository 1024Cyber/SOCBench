import random, time
from scapy.all import Ether, IP, TCP, sendp, get_if_hwaddr, get_if_addr
from attacks.base import BaseAttack


class PortKnock(BaseAttack):
    def run(self):
        target_ip = self.params.get("target_ip", "")
        seq_raw   = self.params.get("knock_sequence", "7000,8000,9000,7001")
        delay     = float(self.params.get("delay", 0.5))
        repeat    = int(self.params.get("repeat", 3))

        if not target_ip:
            self.log("Port Knock: no target IP", "error"); return

        try:
            sequence = [int(p.strip()) for p in seq_raw.split(",")]
        except ValueError:
            self.log("Port Knock: invalid sequence", "error"); return

        dst_mac = self.resolve_mac(target_ip)
        src_mac = get_if_hwaddr(self.iface)
        src_ip  = get_if_addr(self.iface)
        writer  = self.open_pcap()

        self.log(f"Port Knock → {target_ip}  sequence: {sequence}  repeat: {repeat}x", "warn")

        for run in range(repeat):
            if self._stop.is_set(): break
            self.log(f"Knock sequence run {run+1}/{repeat}", "info")
            for port in sequence:
                if self._stop.is_set(): break
                pkt = (
                    Ether(src=src_mac, dst=dst_mac)
                    / IP(src=src_ip, dst=target_ip, ttl=64)
                    / TCP(sport=random.randint(49152, 65535),
                          dport=port, flags="S",
                          seq=random.randint(0, 0xFFFFFFFF))
                )
                sendp(pkt, iface=self.iface, verbose=False)
                self.write(pkt)
                self.log(f"  Knock → :{port}", "info")
                time.sleep(delay)
            time.sleep(delay * 2)

        writer.close()
        self.log("Port Knocking: sequence complete", "success")
