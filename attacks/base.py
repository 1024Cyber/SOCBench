"""
Base class for all attack modules.
"""
import threading


class BaseAttack:
    def __init__(self, params: dict, log_fn):
        self.params   = params
        self.log      = log_fn
        self.iface    = params.get("iface", "wlan0")
        self.pcap     = params.get("pcap", "/tmp/attack.pcap")
        self._stop    = threading.Event()
        self._writer  = None

    def run(self):
        raise NotImplementedError

    def stop(self):
        self._stop.set()
        if self._writer:
            try:
                self._writer.close()
            except Exception:
                pass

    def open_pcap(self):
        from scapy.all import PcapWriter
        self._writer = PcapWriter(self.pcap, append=False, sync=True)
        return self._writer

    def write(self, pkt):
        if self._writer:
            try:
                self._writer.write(pkt)
            except Exception:
                pass

    def resolve_mac(self, ip: str) -> str:
        """ARP-resolve target MAC. Returns broadcast on failure."""
        from scapy.all import Ether, ARP, srp
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, _ = srp(pkt, iface=self.iface, timeout=2, verbose=False)
        if ans:
            return ans[0][1][ARP].hwsrc
        return "ff:ff:ff:ff:ff:ff"
