#!/usr/bin/env python3
"""
SOC Lab — Flask + SocketIO backend  v2.0
Run: sudo python3 app.py
"""

import os
import sys
import threading
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO

# ── suppress scapy noise ──────────────────────────────────────────────────────
try:
    import logging as _l
    _l.getLogger("scapy.runtime").setLevel(_l.ERROR)
    _l.getLogger("scapy.interactive").setLevel(_l.ERROR)
    from scapy.all import conf as scapy_conf
    scapy_conf.verb = 0
except ImportError:
    sys.exit("[!] pip install scapy flask flask-socketio")

# ── attack imports ────────────────────────────────────────────────────────────
from attacks.scanner          import NetworkScanner
from attacks.arp_spoof        import ArpSpoof
from attacks.mac_flood        import MacFlood
from attacks.syn_flood        import SynFlood
from attacks.udp_flood        import UdpFlood
from attacks.icmp_flood       import IcmpFlood
from attacks.icmp_sweep       import IcmpSweep
from attacks.frag_attack      import FragAttack
from attacks.dns_spoof        import DnsSpoof
from attacks.c2_beacon        import C2Beacon
from attacks.icmp_tunnel      import IcmpTunnel
from attacks.dns_exfil        import DnsExfil
from attacks.port_knock       import PortKnock
from attacks.arp_poison_detect import ArpPoisonDetect
from attacks.rogue_dhcp_detect import RogueDhcpDetect
from attacks.ip_spoof         import IpSpoof
from attacks.ack_flood        import AckFlood
from attacks.rst_injection    import RstInjection
from attacks.slowloris        import Slowloris
from attacks.llmnr_poison     import LlmnrPoison
from attacks.nbtns_poison     import NbtnsPoison
from attacks.mdns_poison      import MdnsPoison
from attacks.syn_scan         import SynScan
from attacks.os_fingerprint   import OsFingerprint
# ── nmap advanced
from attacks.nmap_xmas        import NmapXmasScan
from attacks.nmap_tcp         import NmapTcpScan
from attacks.nmap_null        import NmapNullScan
from attacks.nmap_fin         import NmapFinScan
from attacks.nmap_decoy       import NmapDecoyScan
from attacks.nmap_spoof_mac   import NmapSpoofMac
from attacks.nmap_spoof_ip    import NmapSpoofIp
from attacks.nmap_source_port import NmapSourcePort
# ── hping3 advanced
from attacks.hping3_icmp      import Hping3Icmp
from attacks.hping3_syn       import Hping3Syn
from attacks.hping3_rand_source import Hping3RandSource

ATTACK_MAP = {
    # ── existing
    "arp_spoof"         : ArpSpoof,
    "mac_flood"         : MacFlood,
    "syn_flood"         : SynFlood,
    "udp_flood"         : UdpFlood,
    "icmp_flood"        : IcmpFlood,
    "icmp_sweep"        : IcmpSweep,
    "frag_attack"       : FragAttack,
    "dns_spoof"         : DnsSpoof,
    "c2_beacon"         : C2Beacon,
    "icmp_tunnel"       : IcmpTunnel,
    "dns_exfil"         : DnsExfil,
    "port_knock"        : PortKnock,
    "arp_poison_detect" : ArpPoisonDetect,
    "rogue_dhcp_detect" : RogueDhcpDetect,
    "ip_spoof"          : IpSpoof,
    "ack_flood"         : AckFlood,
    "rst_injection"     : RstInjection,
    "slowloris"         : Slowloris,
    "llmnr_poison"      : LlmnrPoison,
    "nbtns_poison"      : NbtnsPoison,
    "mdns_poison"       : MdnsPoison,
    "syn_scan"          : SynScan,
    "os_fingerprint"    : OsFingerprint,
    # ── nmap advanced
    "nmap_xmas"         : NmapXmasScan,
    "nmap_tcp"          : NmapTcpScan,
    "nmap_null"         : NmapNullScan,
    "nmap_fin"          : NmapFinScan,
    "nmap_decoy"        : NmapDecoyScan,
    "nmap_spoof_mac"    : NmapSpoofMac,
    "nmap_spoof_ip"     : NmapSpoofIp,
    "nmap_source_port"  : NmapSourcePort,
    # ── hping3 advanced
    "hping3_icmp"       : Hping3Icmp,
    "hping3_syn"        : Hping3Syn,
    "hping3_rand_source": Hping3RandSource,
}

WIRESHARK_FILTERS = {
    # ── existing
    "arp_spoof"         : "arp.isgratuitous == 1",
    "mac_flood"         : "(eth.src[0] & 0x02) == 0x02",
    "syn_flood"         : "tcp.flags.syn==1 && tcp.flags.ack==0",
    "udp_flood"         : "udp && ip.dst == {target_ip}",
    "icmp_flood"        : "icmp.type==8 && ip.dst=={target_ip}",
    "icmp_sweep"        : "icmp.type==8 || icmp.type==0",
    "frag_attack"       : "ip.flags.mf==1 || ip.frag_offset>0",
    "dns_spoof"         : "dns.flags.response==1",
    "c2_beacon"         : "tcp.flags.syn==1 && ip.dst=={target_ip}",
    "icmp_tunnel"       : "icmp.type==8 && data.len>8",
    "dns_exfil"         : "dns.flags.response==0",
    "port_knock"        : "tcp.flags.syn==1 && ip.dst=={target_ip}",
    "arp_poison_detect" : "arp.opcode==2",
    "rogue_dhcp_detect" : "dhcp.option.dhcp==2",
    "ip_spoof"          : "ip.dst=={target_ip}",
    "ack_flood"         : "tcp.flags.ack==1 && tcp.flags.syn==0 && ip.dst=={target_ip}",
    "rst_injection"     : "tcp.flags.reset==1",
    "slowloris"         : "tcp.dstport=={target_port} && ip.dst=={target_ip}",
    "llmnr_poison"      : "udp.port==5355",
    "nbtns_poison"      : "udp.port==137",
    "mdns_poison"       : "udp.port==5353",
    "syn_scan"          : "tcp.flags.syn==1 && tcp.flags.ack==0 && ip.dst=={target_ip}",
    "os_fingerprint"    : "tcp && ip.dst=={target_ip}",
    # ── nmap advanced
    "nmap_xmas"         : "tcp.flags==0x029 && ip.dst=={target_ip}",
    "nmap_tcp"          : "tcp && ip.dst=={target_ip}",
    "nmap_null"         : "tcp.flags==0x000 && ip.dst=={target_ip}",
    "nmap_fin"          : "tcp.flags==0x001 && ip.dst=={target_ip}",
    "nmap_decoy"        : "tcp.flags.syn==1 && ip.dst=={target_ip}",
    "nmap_spoof_mac"    : "(eth.src[0] & 0x02) == 0x02 && ip.dst=={target_ip}",
    "nmap_spoof_ip"     : "tcp.flags.syn==1 && ip.dst=={target_ip}",
    "nmap_source_port"  : "tcp.flags.syn==1 && tcp.srcport=={source_port} && ip.dst=={target_ip}",
    # ── hping3 advanced
    "hping3_icmp"       : "icmp && ip.dst=={target_ip}",
    "hping3_syn"        : "tcp.flags.syn==1 && ip.dst=={target_ip}",
    "hping3_rand_source": "ip.dst=={target_ip}",
}

# ── Flask / SocketIO ──────────────────────────────────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = "soc-lab-secret-v2"
sio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

CWD      = os.getcwd()
PCAP_DIR = os.path.join(CWD, "pcap_analysis")
os.makedirs(PCAP_DIR, exist_ok=True)

state = {
    "iface"       : None,
    "targets"     : [],
    "scan_running": False,
    "atk_running" : False,
    "atk_instance": None,
    "pcap_file"   : None,
}


# ── helpers ───────────────────────────────────────────────────────────────────
def emit_log(msg: str, level: str = "info"):
    ts = datetime.now().strftime("%H:%M:%S")
    sio.emit("log", {"ts": ts, "msg": msg, "level": level})


def make_pcap_path(attack: str) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(PCAP_DIR, f"{attack}_{ts}.pcap")


def build_wireshark_cmd(attack: str, pcap: str, params: dict) -> tuple[str, str]:
    template = WIRESHARK_FILTERS.get(attack, "")
    filt     = template.format(
        target_ip   = params.get("target_ip", ""),
        target_port = params.get("target_port", ""),
        source_port = params.get("source_port", ""),
    )
    cmd = f'wireshark -r "{pcap}"'
    if filt:
        cmd += f' -Y "{filt}"'
    return filt, cmd


# ── routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/interfaces")
def get_interfaces():
    try:
        from scapy.all import get_if_list
        ifaces = [i for i in get_if_list() if i != "lo"]
    except Exception:
        ifaces = []
    return jsonify(ifaces)


@app.route("/api/state")
def get_state():
    return jsonify({
        "iface"       : state["iface"],
        "targets"     : state["targets"],
        "scan_running": state["scan_running"],
        "atk_running" : state["atk_running"],
        "pcap_file"   : state["pcap_file"],
        "pcap_dir"    : PCAP_DIR,
    })


@app.route("/api/set_iface", methods=["POST"])
def set_iface():
    if state["iface"]:
        return jsonify({"ok": False, "msg": "Interface already locked. Restart to change."})
    iface = request.json.get("iface", "").strip()
    if not iface:
        return jsonify({"ok": False, "msg": "No interface provided."})
    state["iface"] = iface
    from scapy.all import conf as sc
    sc.iface = iface
    emit_log(f"Interface locked: {iface}", "success")
    return jsonify({"ok": True, "iface": iface})


@app.route("/api/scan", methods=["POST"])
def start_scan():
    if state["scan_running"]:
        return jsonify({"ok": False, "msg": "Scan already running."})
    if not state["iface"]:
        return jsonify({"ok": False, "msg": "Lock interface first."})

    def run_scan():
        state["scan_running"] = True
        state["targets"]      = []
        sio.emit("scan_start")
        emit_log("🔍 Starting 3-pass deep network scan …", "info")

        scanner = NetworkScanner(state["iface"])
        found   = {}

        for pass_num in range(1, 4):
            emit_log(f"  Pass {pass_num}/3 — ARP + ICMP sweep …", "info")
            try:
                results = scanner.scan()
                for r in results:
                    if r["ip"] not in found:
                        found[r["ip"]] = r
                        emit_log(
                            f"  {r['ip']:<18} {r['mac']}  {r.get('hostname','')}",
                            "success"
                        )
            except Exception as e:
                emit_log(f"  Scan pass {pass_num} error: {e}", "error")

        state["targets"] = list(found.values())
        emit_log(f"✔ Scan complete — {len(state['targets'])} host(s) found.", "success")
        emit_log(f"  PCAP directory: {PCAP_DIR}", "info")
        sio.emit("scan_done", {"targets": state["targets"]})
        state["scan_running"] = False

    threading.Thread(target=run_scan, daemon=True).start()
    return jsonify({"ok": True})


@app.route("/api/attack/start", methods=["POST"])
def start_attack():
    if state["atk_running"]:
        return jsonify({"ok": False, "msg": "Attack already running — stop it first."})
    if not state["iface"]:
        return jsonify({"ok": False, "msg": "No interface selected."})

    data    = request.json or {}
    attack  = data.get("attack", "")
    params  = data.get("params", {})
    params["iface"] = state["iface"]

    cls = ATTACK_MAP.get(attack)
    if not cls:
        return jsonify({"ok": False, "msg": f"Unknown attack: {attack}"})

    pcap = make_pcap_path(attack)
    state["pcap_file"] = pcap
    params["pcap"]     = pcap

    instance = cls(params, log_fn=emit_log)
    state["atk_instance"] = instance

    def run_atk():
        state["atk_running"] = True
        sio.emit("atk_start", {"attack": attack, "pcap": pcap,
                                "pcap_basename": os.path.basename(pcap)})
        emit_log(f"⚡ {attack.upper()} started", "warn")
        emit_log(f"  PCAP → pcap_analysis/{os.path.basename(pcap)}", "info")
        try:
            instance.run()
        except Exception as e:
            emit_log(f"Attack runtime error: {e}", "error")
        finally:
            state["atk_running"]  = False
            state["atk_instance"] = None
            filt, cmd = build_wireshark_cmd(attack, pcap, params)
            sio.emit("atk_done", {"pcap": pcap, "pcap_basename": os.path.basename(pcap)})
            sio.emit("wireshark_cmd", {"cmd": cmd, "filter": filt,
                                        "pcap": pcap, "pcap_basename": os.path.basename(pcap)})
            emit_log(f"■ Stopped. PCAP saved → pcap_analysis/{os.path.basename(pcap)}", "success")
            emit_log(f"  Wireshark: {cmd}", "info")

    threading.Thread(target=run_atk, daemon=True).start()
    return jsonify({"ok": True, "pcap": pcap})


@app.route("/api/attack/stop", methods=["POST"])
def stop_attack():
    inst = state.get("atk_instance")
    if inst:
        inst.stop()
        emit_log("Stop signal sent — waiting for attack to finish …", "warn")
    return jsonify({"ok": True})


@app.route("/api/pcaps")
def list_pcaps():
    try:
        files = sorted(
            [f for f in os.listdir(PCAP_DIR) if f.endswith(".pcap")],
            reverse=True
        )
    except Exception:
        files = []
    return jsonify(files)


# ── run ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("[!] Must run as root: sudo python3 app.py")
    print(f"\n  ╔══════════════════════════════════════╗")
    print(f"  ║  SOC Lab  —  http://127.0.0.1:4586  ║")
    print(f"  ║  PCAP dir: ./pcap_analysis/          ║")
    print(f"  ╚══════════════════════════════════════╝\n")
    sio.run(app, host="127.0.0.1", port=4586, debug=False, use_reloader=False)
