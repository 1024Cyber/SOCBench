"""
hping3 SYN Packet Customization  — hping3 -S --tcp-timestamp --win N --ttl N
Crafts TCP SYN packets with fully controllable window size, TTL, flags,
IP ID, sequence number, and optional TCP timestamp option.
Used to test firewall/IDS rules and fingerprint stack behaviour.
"""
import time, random, struct
from scapy.all import (Ether, IP, TCP, ARP, srp, sendp,
                        get_if_hwaddr, TCPOptions)
from attacks.base import BaseAttack


class Hping3Syn(BaseAttack):
    def run(self):
        target_ip   = self.params.get("target_ip", "")
        target_port = int(self.params.get("target_port", 80))
        source_port = self.params.get("source_port", "random")
        window_size = int(self.params.get("window_size", 65535))
        ttl         = int(self.params.get("ttl", 64))
        flags_str   = self.params.get("flags", "S")
        ip_id       = self.params.get("ip_id", "random")
        seq         = self.params.get("seq", "random")
        use_ts      = self.params.get("tcp_timestamp", "yes").lower() == "yes"
        count       = int(self.params.get("count", 100))
        interval    = float(self.params.get("interval", 0.1))

        if not target_ip:
            self.log("hping3 SYN: no target IP", "error"); return

        arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
        ans, _  = srp(arp_pkt, iface=self.iface, timeout=2, verbose=False)
        dst_mac = ans[0][1][ARP].hwsrc if ans else "ff:ff:ff:ff:ff:ff"
        src_mac = get_if_hwaddr(self.iface)
        writer  = self.open_pcap()

        self.log(
            f"hping3 SYN Custom → {target_ip}:{target_port}  "
            f"flags={flags_str}  win={window_size}  ttl={ttl}  ts={use_ts}  count={count}",
            "warn"
        )

        sent = 0
        while not self._stop.is_set():
            if count and sent >= count:
                break

            sport  = random.randint(1024, 65535) if source_port == "random" else int(source_port)
            ip_id_ = random.randint(0, 0xFFFF)  if ip_id     == "random" else int(ip_id)
            seq_   = random.randint(0, 0xFFFFFFFF) if seq     == "random" else int(seq)

            # Build TCP options
            opts = []
            if use_ts:
                ts_val = int(time.time()) & 0xFFFFFFFF
                opts.append(("Timestamp", (ts_val, 0)))
            opts += [("MSS", 1460), ("SAckOK", "")]

            pkt = (
                Ether(src=src_mac, dst=dst_mac)
                / IP(dst=target_ip, ttl=ttl, id=ip_id_)
                / TCP(dport=target_port, sport=sport, flags=flags_str,
                      window=window_size, seq=seq_, options=opts)
            )
            try:
                sendp(pkt, iface=self.iface, verbose=False)
                self.write(pkt)
                sent += 1
                if sent % 25 == 0:
                    self.log(f"  SYN custom: {sent}/{count} sent", "info")
            except Exception as e:
                self.log(f"hping3 SYN error: {e}", "error"); break
            time.sleep(interval)

        writer.close()
        self.log(f"hping3 SYN custom done — {sent} packets sent", "success")
