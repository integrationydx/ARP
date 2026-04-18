"""
SDN Firewall Controller — Ryu OpenFlow 1.3
==========================================
Features:
  - Learning Switch (MAC-to-port table)
  - IP + ARP Firewall (blocked host pairs)
  - Proactive OpenFlow DROP rules (priority 10, with timeouts)
  - Full Packet Logger (ARP / ICMP / TCP / UDP / IPv4 / IPv6 / LLDP)
  - Flow statistics logging (packet count, byte count per rule)
  - Packet counter per switch (monitoring)

Blocked Rule:  h1 (10.0.0.1) <--X--> h3 (10.0.0.3)  [bidirectional]
Allowed:       all other host pairs communicate freely
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, ipv6, arp, tcp, udp, icmp


class SDNFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNFirewall, self).__init__(*args, **kwargs)

        # MAC learning table: {dpid: {mac: port}}
        self.mac_to_port = {}

        # Packet counter per switch for monitoring
        self.packet_count = {}

        # ------------------------------------------------------------------
        # FIREWALL RULES: (src_ip, dst_ip) pairs to block — bidirectional
        # ------------------------------------------------------------------
        self.blocked_pairs = [
            ("10.0.0.1", "10.0.0.3"),  # h1 → h3  BLOCKED
            ("10.0.0.3", "10.0.0.1"),  # h3 → h1  BLOCKED (bidirectional)
        ]

        self.logger.info("=" * 60)
        self.logger.info("  SDN Firewall Controller Initialized")
        self.logger.info("  Blocked pairs: %s", self.blocked_pairs)
        self.logger.info("=" * 60)

    # =========================================================================
    # SWITCH HANDSHAKE: Install table-miss flow entry
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info("[SWITCH] Connected: dpid=%016x", datapath.id)

        # Table-miss entry: priority 0, match everything → send to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)

    # =========================================================================
    # HELPER: Install a FORWARD flow rule
    # =========================================================================
    def add_flow(self, datapath, priority, match, actions,
                 buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]

        kwargs = dict(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )
        if buffer_id and buffer_id != ofproto.OFP_NO_BUFFER:
            kwargs['buffer_id'] = buffer_id

        datapath.send_msg(parser.OFPFlowMod(**kwargs))

    # =========================================================================
    # HELPER: Install a DROP flow rule (empty action list = drop)
    # =========================================================================
    def add_drop_flow(self, datapath, priority, match,
                      idle_timeout=30, hard_timeout=60):
        parser = datapath.ofproto_parser

        # No actions = DROP
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=[],           # empty → switch drops the packet
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )
        datapath.send_msg(mod)
        self.logger.info("[FLOW] DROP rule installed: %s", match)

    # =========================================================================
    # PACKET LOGGER: Identify protocol type & display full packet info
    # =========================================================================
    def log_packet_info(self, dpid, in_port, eth, pkt):
        protocol = "UNKNOWN"
        extra = ""

        ip_pkt  = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip6_pkt = pkt.get_protocol(ipv6.ipv6)

        if arp_pkt:
            # ---- ARP -------------------------------------------------------
            protocol = "ARP"
            op = "REQUEST" if arp_pkt.opcode == 1 else "REPLY"
            extra = "op=%-7s src_ip=%-15s dst_ip=%-15s src_mac=%s" % (
                op, arp_pkt.src_ip, arp_pkt.dst_ip, arp_pkt.src_mac)

        elif ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst

            tcp_pkt  = pkt.get_protocol(tcp.tcp)
            udp_pkt  = pkt.get_protocol(udp.udp)
            icmp_pkt = pkt.get_protocol(icmp.icmp)

            if tcp_pkt:
                # ---- TCP ---------------------------------------------------
                protocol = "TCP"
                flags = []
                if tcp_pkt.bits & 0x02: flags.append("SYN")
                if tcp_pkt.bits & 0x10: flags.append("ACK")
                if tcp_pkt.bits & 0x01: flags.append("FIN")
                if tcp_pkt.bits & 0x04: flags.append("RST")
                extra = "src_ip=%-15s dst_ip=%-15s sport=%5d dport=%5d flags=%s" % (
                    src_ip, dst_ip,
                    tcp_pkt.src_port, tcp_pkt.dst_port,
                    "|".join(flags) if flags else "NONE")

            elif udp_pkt:
                # ---- UDP ---------------------------------------------------
                protocol = "UDP"
                extra = "src_ip=%-15s dst_ip=%-15s sport=%5d dport=%5d" % (
                    src_ip, dst_ip, udp_pkt.src_port, udp_pkt.dst_port)

            elif icmp_pkt:
                # ---- ICMP --------------------------------------------------
                protocol = "ICMP"
                icmp_type = {8: "ECHO_REQ", 0: "ECHO_REP",
                             3: "UNREACH",  11: "TTL_EXP"}.get(
                    icmp_pkt.type, str(icmp_pkt.type))
                extra = "src_ip=%-15s dst_ip=%-15s type=%-10s code=%d" % (
                    src_ip, dst_ip, icmp_type, icmp_pkt.code)

            else:
                # ---- Other IPv4 --------------------------------------------
                protocol = "IPv4"
                extra = "src_ip=%-15s dst_ip=%-15s proto=%d ttl=%d" % (
                    src_ip, dst_ip, ip_pkt.proto, ip_pkt.ttl)

        elif ip6_pkt:
            # ---- IPv6 ------------------------------------------------------
            protocol = "IPv6"
            extra = "src=%s dst=%s" % (ip6_pkt.src, ip6_pkt.dst)

        elif eth.ethertype == 0x88cc:
            # ---- LLDP ------------------------------------------------------
            protocol = "LLDP"
            extra = "(Link Layer Discovery — skipped)"

        self.logger.info(
            "[PKT] dpid=%016x port=%-3s | ETH src=%-17s dst=%-17s "
            "| Proto=%-6s | %s",
            dpid, in_port, eth.src, eth.dst, protocol, extra
        )

    # =========================================================================
    # PACKET-IN HANDLER: Core controller logic
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        dpid     = datapath.id
        in_port  = msg.match['in_port']

        # Initialise per-switch data structures
        self.mac_to_port.setdefault(dpid, {})
        self.packet_count.setdefault(dpid, 0)
        self.packet_count[dpid] += 1

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP silently
        if eth.ethertype == 0x88cc:
            return

        dst = eth.dst
        src = eth.src

        # ------------------------------------------------------------------
        # 📋 PACKET LOGGER — identify protocol and display full info
        # ------------------------------------------------------------------
        self.log_packet_info(dpid, in_port, eth, pkt)

        # Learn source MAC → port mapping
        self.mac_to_port[dpid][src] = in_port

        # ------------------------------------------------------------------
        # 🔴 FIREWALL: Block IP traffic between forbidden host pairs
        #    Install an OpenFlow DROP rule so future packets never hit ctrl
        # ------------------------------------------------------------------
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst

            if (src_ip, dst_ip) in self.blocked_pairs:
                self.logger.warning(
                    "[FIREWALL] ❌ BLOCKED IP  %s → %s "
                    "(dpid=%016x, total_pkts_seen=%d)",
                    src_ip, dst_ip, dpid, self.packet_count[dpid]
                )
                # Install proactive DROP flow — higher priority than forwarding
                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ipv4_src=src_ip,
                    ipv4_dst=dst_ip
                )
                self.add_drop_flow(datapath, priority=10, match=match,
                                   idle_timeout=30, hard_timeout=60)
                return  # Drop this packet immediately

        # ------------------------------------------------------------------
        # 🔴 FIREWALL: Also block ARP between forbidden pairs
        #    Prevents host discovery and MAC address leakage
        # ------------------------------------------------------------------
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip

            if (src_ip, dst_ip) in self.blocked_pairs:
                self.logger.warning(
                    "[FIREWALL] ❌ BLOCKED ARP %s → %s (dpid=%016x)",
                    src_ip, dst_ip, dpid
                )
                return  # Drop ARP packet

        # ------------------------------------------------------------------
        # ✅ LEARNING SWITCH: Forward or flood
        # ------------------------------------------------------------------
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            self.logger.info(
                "[SWITCH] ✅ FORWARD src=%s dst=%s port=%s→%s",
                src, dst, in_port, out_port
            )
        else:
            out_port = ofproto.OFPP_FLOOD
            self.logger.info(
                "[SWITCH] 🌊 FLOOD   src=%s dst=%s (unknown dst)",
                src, dst
            )

        actions = [parser.OFPActionOutput(out_port)]

        # Install forwarding flow rule (avoids hitting controller next time)
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port, eth_dst=dst, eth_src=src)

            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, priority=1, match=match,
                              actions=actions, buffer_id=msg.buffer_id,
                              idle_timeout=10, hard_timeout=30)
                return  # packet already handled via buffer
            else:
                self.add_flow(datapath, priority=1, match=match,
                              actions=actions,
                              idle_timeout=10, hard_timeout=30)

        # Send current packet out
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)

    # =========================================================================
    # 📊 FLOW STATS REPLY: Log flow table entries with packet/byte counts
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        self.logger.info("=" * 60)
        self.logger.info("[STATS] Flow Table — dpid=%016x", dpid)
        self.logger.info("=" * 60)
        for stat in sorted(ev.msg.body,
                           key=lambda s: (s.priority, str(s.match)),
                           reverse=True):
            self.logger.info(
                "  priority=%-3s | packets=%-8s | bytes=%-10s | "
                "idle_timeout=%-4s | match=%s | actions=%s",
                stat.priority,
                stat.packet_count,
                stat.byte_count,
                stat.idle_timeout,
                stat.match,
                stat.instructions,
            )
        self.logger.info("=" * 60)