from scapy.all import DHCP, IP, sniff
from attacks.base import BaseAttack


class RogueDhcpDetect(BaseAttack):
    def run(self):
        known = self.params.get("known_server", "")
        writer = self.open_pcap()
        seen   = {}
        self.log(f"Rogue DHCP Detector: listening on {self.iface} …", "info")
        if known:
            self.log(f"  Known-good server: {known}", "info")

        def handle(pkt):
            if not pkt.haslayer(DHCP) or not pkt.haslayer(IP):
                return
            opts = {o[0]: o[1] for o in pkt[DHCP].options if isinstance(o, tuple)}
            if opts.get("message-type") != 2:
                return
            src = pkt[IP].src
            self.write(pkt)
            seen[src] = seen.get(src, 0) + 1

            if known and src == known:
                self.log(f"  DHCP OFFER from known server {src} (#{seen[src]})", "info")
            else:
                self.log(f"🚨 ROGUE DHCP SERVER: {src} — offer #{seen[src]}", "error")

        sniff(
            iface=self.iface,
            filter="udp and (port 67 or port 68)",
            prn=handle,
            store=False,
            stop_filter=lambda _: self._stop.is_set(),
        )
        writer.close()
        self.log("Rogue DHCP Detector: stopped", "info")
